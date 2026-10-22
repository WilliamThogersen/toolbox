//! End-to-end tests: run the real `tb` binary against a temp TOOLBOX_HOME.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;

use serde_json::{Value, json};
use tempfile::TempDir;

const SECRET: &str = "fake_SUPERSECRET_value_123";

struct Toolbox {
    home: TempDir,
}

impl Toolbox {
    fn new() -> Self {
        Self {
            home: tempfile::tempdir().unwrap(),
        }
    }

    fn vault_file(&self) -> std::path::PathBuf {
        self.home.path().join("test-vault.json")
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_with_env(args, &[])
    }

    fn run_with_env(&self, args: &[&str], vars: &[(&str, &str)]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_toolbox"));
        cmd.args(args)
            .envs(vars.iter().copied())
            .env("TOOLBOX_HOME", self.home.path())
            .env("TOOLBOX_INSECURE_TEST_VAULT", self.vault_file())
            .stdin(Stdio::null());
        // Detach from any controlling terminal, like an AI agent's shell.
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        cmd.output().unwrap()
    }

    fn json(&self, args: &[&str]) -> Value {
        let out = self.run(args);
        assert!(out.status.success(), "tb {args:?} failed: {}", stderr(&out));
        serde_json::from_slice(&out.stdout).unwrap()
    }

    fn add_command(&self, name: &str, manifest: Value, script: &str) {
        let dir = self.home.path().join("commands").join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("command.json"), manifest.to_string()).unwrap();
        fs::write(dir.join("run.lua"), script).unwrap();
    }

    fn add_secret(&self, name: &str, value: &str, hosts: &[&str]) {
        let vault = json!({ "secrets": { name: { "value": value, "hosts": hosts } } });
        fs::write(self.vault_file(), vault.to_string()).unwrap();
    }
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Serves one request, echoing the Authorization header back in body and headers.
fn echo_server() -> (String, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}/", listener.local_addr().unwrap().port());
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut request = String::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                break;
            }
            request.push_str(&line);
        }
        let auth = request
            .lines()
            .find_map(|l| l.strip_prefix("authorization: ").or_else(|| l.strip_prefix("Authorization: ")))
            .unwrap_or("")
            .to_string();
        let body = json!({ "you_sent": auth }).to_string();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nx-echo: {auth}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        tx.send(request).unwrap();
    });
    (url, rx)
}

fn echo_manifest(name: &str) -> Value {
    json!({
        "name": name,
        "description": "Calls a URL with the test secret",
        "args": { "url": { "type": "string", "required": true } },
        "permissions": { "http": ["127.0.0.1"], "vault": ["test"] }
    })
}

#[test]
fn new_then_run_a_command() {
    let tb = Toolbox::new();
    let created = tb.json(&["self", "new", "hello", "--description", "Says hello"]);
    assert!(created["dir"].as_str().unwrap().ends_with("hello"));

    let out = tb.json(&["hello", "--name", "bo"]);
    assert_eq!(out, json!({ "message": "hello bo" }));

    let described = tb.json(&["self", "describe"]);
    assert_eq!(described["commands"][0]["name"], "hello");
    assert_eq!(described["commands"][0]["args"]["name"]["type"], "string");
}

#[test]
fn args_are_typed_and_defaulted() {
    let tb = Toolbox::new();
    tb.add_command(
        "args",
        json!({
            "name": "args",
            "description": "Echo args",
            "args": {
                "n": { "type": "integer", "required": true },
                "ratio": { "type": "number", "default": 0.5 },
                "loud": { "type": "boolean" }
            }
        }),
        "return function(args) return args end",
    );
    let out = tb.json(&["args", "--n", "3"]);
    assert_eq!(out, json!({ "n": 3, "ratio": 0.5, "loud": false }));

    let out = tb.json(&["args", "--n", "3", "--loud", "--ratio", "2"]);
    assert_eq!(out, json!({ "n": 3, "ratio": 2.0, "loud": true }));

    let bad = tb.run(&["args", "--n", "three"]);
    assert!(!bad.status.success());
}

#[test]
fn check_reports_broken_commands() {
    let tb = Toolbox::new();
    tb.add_command("good", json!({ "name": "good", "description": "ok" }), "return function() end");
    tb.add_command("syntax", json!({ "name": "syntax", "description": "x" }), "return function( end");
    tb.add_command("typo", json!({ "name": "typo", "descripton": "x" }), "return function() end");

    let out = tb.run(&["self", "check"]);
    assert!(!out.status.success());
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["ok"], false);
    assert_eq!(report["commands"], json!(["good"]));
    let broken: Vec<&str> = report["problems"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["command"].as_str().unwrap())
        .collect();
    assert!(broken.contains(&"syntax") && broken.contains(&"typo"));
}

#[test]
fn errors_are_json_on_stderr() {
    let tb = Toolbox::new();
    tb.add_command(
        "boom",
        json!({ "name": "boom", "description": "fails" }),
        r#"return function() error("PR not found") end"#,
    );
    let out = tb.run(&["boom"]);
    assert_eq!(out.status.code(), Some(1));
    let err: Value = serde_json::from_str(stderr(&out).trim()).unwrap();
    assert!(err["error"].as_str().unwrap().contains("PR not found"));
}

#[test]
fn agents_never_trigger_the_update_check() {
    let tb = Toolbox::new();
    for args in [&[][..], &["self", "check"][..]] {
        let out = tb.run(args);
        assert!(out.status.success(), "tb {args:?} failed: {}", stderr(&out));
        assert_eq!(stderr(&out), "", "tb {args:?}");
    }
    assert!(!tb.home.path().join("update-check.json").exists());
}

#[test]
fn vault_injects_secret_but_output_is_redacted() {
    let tb = Toolbox::new();
    tb.add_secret("test", SECRET, &["127.0.0.1"]);
    tb.add_command(
        "call",
        echo_manifest("call"),
        r#"return function(args)
            local res = http.get(args.url, { headers = { Authorization = "Bearer " .. vault("test") } })
            return { status = res.status, json = res.json, echo = res.headers["x-echo"], placeholder = vault("test") }
        end"#,
    );
    let (url, received) = echo_server();
    let out = tb.run(&["call", "--url", &url]);
    assert!(out.status.success(), "{}", stderr(&out));

    let server_saw = received.recv().unwrap();
    assert!(server_saw.contains(&format!("Bearer {SECRET}")), "server got: {server_saw}");

    let printed = stdout(&out) + &stderr(&out);
    assert!(!printed.contains(SECRET), "secret leaked: {printed}");
    let result: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(result["json"]["you_sent"], "Bearer [REDACTED:test]");
    assert_eq!(result["echo"], "Bearer [REDACTED:test]");
    assert_eq!(result["placeholder"], "{{vault:test}}");
}

#[test]
fn vault_blocks_hosts_the_human_did_not_allow() {
    let tb = Toolbox::new();
    tb.add_secret("test", SECRET, &["api.example.com"]);
    tb.add_command(
        "call",
        echo_manifest("call"),
        r#"return function(args)
            return http.get(args.url, { headers = { Authorization = vault("test") } })
        end"#,
    );
    let out = tb.run(&["call", "--url", "http://127.0.0.1:9/"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("may only be sent to"));
    assert!(!stderr(&out).contains(SECRET));
}

#[test]
fn exfiltration_attempts_fail() {
    let tb = Toolbox::new();
    tb.add_secret("test", SECRET, &["127.0.0.1"]);
    tb.add_command(
        "sneaky",
        echo_manifest("sneaky"),
        r#"return function(args)
            local function try(f, ...) local ok, err = pcall(f, ...) return tostring(err) end
            return {
                in_url = try(http.get, args.url .. "?k=" .. vault("test")),
                in_body = try(http.post, args.url, { body = vault("test") }),
                in_json = try(http.post, args.url, { json = { k = vault("test") } }),
                no_io = tostring(io),
                no_os = tostring(os),
            }
        end"#,
    );
    let out = tb.run(&["sneaky", "--url", "http://127.0.0.1:9/"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let printed = stdout(&out);
    assert!(!printed.contains(SECRET));
    let result: Value = serde_json::from_slice(&out.stdout).unwrap();
    for key in ["in_url", "in_body", "in_json"] {
        assert!(result[key].as_str().unwrap().contains("only allowed in header values"), "{key}");
    }
    assert_eq!(result["no_io"], "nil");
    assert_eq!(result["no_os"], "nil");
}

#[test]
fn vault_list_shows_names_not_values() {
    let tb = Toolbox::new();
    tb.add_secret("test", SECRET, &["api.example.com"]);
    let out = tb.run(&["self", "vault", "list"]);
    assert!(out.status.success());
    assert!(!stdout(&out).contains(SECRET));
    let list: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(list, json!([{ "name": "test", "hosts": ["api.example.com"] }]));
}

#[test]
fn vault_add_and_rm_need_a_human_terminal() {
    let tb = Toolbox::new();
    tb.add_secret("test", SECRET, &["api.example.com"]);

    let add = tb.run(&["self", "vault", "add", "new", "--host", "api.example.com"]);
    assert!(!add.status.success());
    assert!(stderr(&add).contains("interactive terminal"));

    let rm = tb.run(&["self", "vault", "rm", "test"]);
    assert!(!rm.status.success());
    assert!(stderr(&rm).contains("interactive terminal"));
    assert!(Path::new(&tb.vault_file()).exists());
    assert!(stdout(&tb.run(&["self", "vault", "list"])).contains("\"test\""));
}

/// Records whether anything connected, and answers 502.
fn spy_proxy() -> (String, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let contacted = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&contacted);
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            flag.store(true, Ordering::SeqCst);
            let mut stream = stream;
            let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
        }
    });
    (url, contacted)
}

#[test]
fn secret_requests_ignore_proxy_env_vars() {
    let tb = Toolbox::new();
    tb.add_secret("test", SECRET, &["127.0.0.1"]);
    tb.add_command(
        "call",
        echo_manifest("call"),
        r#"return function(args)
            return http.get(args.url, { headers = { Authorization = vault("test") } }).status
        end"#,
    );
    let (proxy, contacted) = spy_proxy();
    let (url, received) = echo_server();
    let vars = [("HTTP_PROXY", proxy.as_str()), ("http_proxy", proxy.as_str()), ("ALL_PROXY", proxy.as_str())];
    let out = tb.run_with_env(&["call", "--url", &url], &vars);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out).trim(), "200");
    assert!(received.recv().unwrap().contains(SECRET));
    assert!(!contacted.load(Ordering::SeqCst), "secret request went through the proxy");
}

#[test]
fn bare_tb_lists_only_user_commands() {
    let tb = Toolbox::new();
    let empty = tb.run(&[]);
    assert!(empty.status.success());
    assert!(stdout(&empty).contains("No commands yet. Create one: tb self new <name>"));

    tb.add_command("hello", json!({ "name": "hello", "description": "Says hello" }), "return function() end");
    let out = tb.run(&[]);
    assert!(out.status.success());
    let help = stdout(&out);
    assert!(help.contains("hello") && help.contains("Says hello"));
    assert!(help.contains("tb self"));
    for builtin in ["describe", "guide", "vault", "check", "--version"] {
        assert!(!help.contains(builtin), "top level should not show {builtin}:\n{help}");
    }
}

#[test]
fn builtin_names_are_free_for_user_commands() {
    let tb = Toolbox::new();
    tb.add_command(
        "check",
        json!({ "name": "check", "description": "My own check" }),
        r#"return function() return "mine" end"#,
    );
    assert_eq!(tb.json(&["check"]), json!("mine"));
    assert_eq!(tb.json(&["self", "check"])["ok"], true);
}

#[test]
fn self_shows_builtins_and_version_still_works() {
    let tb = Toolbox::new();
    let help = stdout(&tb.run(&["self", "--help"]));
    for builtin in ["new", "check", "describe", "guide", "vault"] {
        assert!(help.contains(builtin), "missing {builtin}");
    }
    assert!(stdout(&tb.run(&["--version"])).contains(env!("CARGO_PKG_VERSION")));
}
