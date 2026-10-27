//! End-to-end tests: run the real `tb` binary against a temp `TOOLBOX_HOME`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::needless_pass_by_value,
    reason = "test code: a panic is a failed test, and helpers take `json!(...)` values as they are"
)]

mod common;

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use common::pty::{self, Pty};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
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
        let mut cmd = self.command(args);
        cmd.envs(vars.iter().copied()).stdin(Stdio::null());
        cmd.output().unwrap()
    }

    /// Like `run_with_env`, but kills `tb` after `limit`, so a run that never ends
    /// fails the test instead of hanging it. `None` means it was killed.
    fn run_within(&self, args: &[&str], vars: &[(&str, &str)], limit: Duration) -> Option<Output> {
        let mut child = self
            .command(args)
            .envs(vars.iter().copied())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + limit;
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                return None;
            }
            thread::sleep(Duration::from_millis(20));
        }
        Some(child.wait_with_output().unwrap())
    }

    /// Runs in `dir` with `input` piped to stdin, like `echo input | tb ...` there.
    fn run_piped(&self, args: &[&str], dir: &Path, input: &str) -> Output {
        let mut child = self
            .command(args)
            .current_dir(dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
        child.wait_with_output().unwrap()
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_toolbox"));
        cmd.args(args)
            .env("TOOLBOX_HOME", self.home.path())
            .env("TOOLBOX_INSECURE_TEST_VAULT", self.vault_file());
        common::detach(&mut cmd);
        cmd
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

    /// Writes `command.json` and each `(path, text)` file, folders included.
    fn add_files(&self, name: &str, manifest: Value, files: &[(&str, &str)]) {
        let dir = self.home.path().join("commands").join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("command.json"), manifest.to_string()).unwrap();
        for (path, text) in files {
            let file = dir.join(path);
            fs::create_dir_all(file.parent().unwrap()).unwrap();
            fs::write(file, text).unwrap();
        }
    }

    fn add_secret(&self, name: &str, value: &str, hosts: &[&str]) {
        self.edit_vault(|vault| vault["keys"][name] = json!({ "value": value, "hosts": hosts }));
    }

    /// What `tb self vault allow` stores, written directly: tests have no terminal to say yes on.
    fn allow(&self, secret: &str, command: &str) {
        let dir = self.home.path().join("commands").join(command);
        let manifest = fs::read_to_string(dir.join("command.json")).unwrap();
        let script = fs::read_to_string(dir.join("run.lua")).unwrap();
        let approved = fingerprint(&manifest, &script);
        self.edit_vault(|vault| vault["keys"][secret]["commands"][command] = json!(approved));
    }

    /// Like `allow`, for a command whose Lua files are `paths` rather than only run.lua.
    fn allow_files(&self, secret: &str, command: &str, paths: &[&str]) {
        let dir = self.home.path().join("commands").join(command);
        let manifest = fs::read_to_string(dir.join("command.json")).unwrap();
        let files: Vec<(String, String)> = paths
            .iter()
            .map(|path| (path.to_string(), fs::read_to_string(dir.join(path)).unwrap()))
            .collect();
        let approved = files_fingerprint(&manifest, &files);
        self.edit_vault(|vault| vault["keys"][secret]["commands"][command] = json!(approved));
    }

    fn edit_vault(&self, change: impl FnOnce(&mut Value)) {
        let mut vault: Value = fs::read(self.vault_file()).map_or_else(|_| json!({ "format": 2, "keys": {} }), |bytes| serde_json::from_slice(&bytes).unwrap());
        change(&mut vault);
        fs::write(self.vault_file(), vault.to_string()).unwrap();
    }

    fn vault(&self) -> Value {
        serde_json::from_slice(&fs::read(self.vault_file()).unwrap()).unwrap()
    }
}

/// Mirrors `vault::approval::fingerprint`. Changing it there drops every approval users have stored.
fn fingerprint(manifest: &str, script: &str) -> String {
    let mut hasher = Sha256::new();
    for part in [manifest, script] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    hasher.finalize().iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().concat()
}

/// Mirrors `vault::approval::files_fingerprint`: every Lua file with its path, sorted, after a tag
/// that keeps it apart from the two-file `fingerprint`.
fn files_fingerprint(manifest: &str, files: &[(String, String)]) -> String {
    let mut sorted: Vec<&(String, String)> = files.iter().collect();
    sorted.sort();
    let mut hasher = Sha256::new();
    hasher.update(b"toolbox files v1\n");
    let parts = std::iter::once(manifest).chain(sorted.iter().flat_map(|(path, text)| [path.as_str(), text.as_str()]));
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    hasher.finalize().iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().concat()
}

/// `127.0.0.1:1234` from `http://127.0.0.1:1234/`, as a `--host` rule.
fn host_of(url: &str) -> &str {
    url.trim_start_matches("http://").trim_end_matches('/')
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Reads a request line and headers, up to the blank line after them.
fn read_head(stream: &TcpStream) -> String {
    let mut reader = BufReader::new(stream);
    let mut head = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
            break;
        }
        head.push_str(&line);
    }
    head
}

/// Serves one request, echoing the Authorization header back in body and headers,
/// and the path with its query in the body.
fn echo_server() -> (String, mpsc::Receiver<String>) {
    serve_echo(|auth, path| json!({ "you_sent": auth, "path": path }).to_string())
}

/// Like `echo_server`, but writes every character of the echoed header in the body as
/// a JSON `\uXXXX` escape, so the raw body never contains the key as typed.
fn escaping_echo_server() -> (String, mpsc::Receiver<String>) {
    serve_echo(|auth, path| format!(r#"{{"you_sent":"{}","path":{}}}"#, json_escaped(auth), json!(path)))
}

/// Echoes the Authorization header as a bare JSON string, every character escaped.
fn bare_string_echo_server() -> (String, mpsc::Receiver<String>) {
    serve_echo(|auth, _| format!(r#""{}""#, json_escaped(auth)))
}

fn json_escaped(text: &str) -> String {
    text.chars().map(|c| format!("\\u{:04x}", u32::from(c))).collect::<Vec<_>>().concat()
}

/// Serves one request, answering with `body(authorization header, path)`.
fn serve_echo(body: fn(&str, &str) -> String) -> (String, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}/", listener.local_addr().unwrap().port());
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_head(&stream);
        let auth = request
            .lines()
            .find_map(|l| l.strip_prefix("authorization: ").or_else(|| l.strip_prefix("Authorization: ")))
            .unwrap_or("")
            .to_string();
        let path = request.split(' ').nth(1).unwrap_or("").to_string();
        let body = body(&auth, &path);
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
fn runaway_scripts_stop_at_the_cpu_limit_even_when_they_catch_it() {
    let tb = Toolbox::new();
    let scripts = [
        ("spin", "while true do end"),
        ("catch", "while true do pcall(function() while true do end end) end"),
        ("resume", "while true do coroutine.resume(coroutine.create(function() while true do end end)) end"),
    ];
    for (name, body) in scripts {
        let manifest = json!({ "name": name, "description": "x", "limits": { "cpu_seconds": 0.3 } });
        tb.add_command(name, manifest, &format!("return function() {body} end"));
        let out = tb
            .run_within(&[name], &[], Duration::from_secs(15))
            .unwrap_or_else(|| panic!("{name} was still running after 15s"));
        assert_eq!(out.status.code(), Some(1), "{name}");
        let err: Value = serde_json::from_str(stderr(&out).trim()).unwrap();
        let message = err["error"].as_str().unwrap();
        assert!(message.contains(&format!("command \"{name}\" failed")) && message.contains("0.3s of CPU time"), "{message}");
    }
}

#[test]
fn runaway_memory_stops_at_the_memory_limit() {
    let tb = Toolbox::new();
    tb.add_command(
        "hog",
        json!({ "name": "hog", "description": "x", "limits": { "memory_mb": 32 } }),
        "return function() local t = {} for i = 1, 1e9 do t[i] = i end end",
    );
    let out = tb
        .run_within(&["hog"], &[], Duration::from_secs(15))
        .expect("hog was still running after 15s");
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("more than 32 MB of memory"), "{}", stderr(&out));
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
fn init_imports_the_instructions_into_claude_md_once_and_remove_undoes_it() {
    let tb = Toolbox::new();
    let claude = tempfile::tempdir().unwrap();
    let claude_md = claude.path().join("CLAUDE.md");
    let original = "# Mine\n\n@RTK.md\n";
    fs::write(&claude_md, original).unwrap();
    let env = [("CLAUDE_CONFIG_DIR", claude.path().to_str().unwrap())];
    let init = |args: &[&str]| {
        let out = tb.run_with_env(args, &env);
        assert!(out.status.success(), "tb {args:?} failed: {}", stderr(&out));
        serde_json::from_slice::<Value>(&out.stdout).unwrap()
    };

    let first = init(&["self", "init"]);
    assert_eq!((first["imported"].clone(), first["updated"].clone()), (json!(true), json!(true)));
    assert_eq!(fs::read_to_string(&claude_md).unwrap(), "# Mine\n\n@RTK.md\n\n@TOOLBOX.md\n");
    let instructions = fs::read_to_string(claude.path().join("TOOLBOX.md")).unwrap();
    assert!(instructions.contains("tb self guide"), "{instructions}");

    let again = init(&["self", "init"]);
    assert_eq!((again["imported"].clone(), again["updated"].clone()), (json!(false), json!(false)));
    assert_eq!(fs::read_to_string(&claude_md).unwrap(), "# Mine\n\n@RTK.md\n\n@TOOLBOX.md\n");

    let removed = init(&["self", "init", "--remove"]);
    assert_eq!((removed["import_removed"].clone(), removed["deleted"].clone()), (json!(true), json!(true)));
    assert_eq!(fs::read_to_string(&claude_md).unwrap(), original);
    assert!(!claude.path().join("TOOLBOX.md").exists());
}

#[test]
fn keys_hidden_in_json_escapes_are_redacted_too() {
    let tb = Toolbox::new();
    let (url, _received) = escaping_echo_server();
    tb.add_secret("test", SECRET, &[host_of(&url)]);
    tb.add_command(
        "call",
        echo_manifest("call"),
        r#"return function(args)
            local res = http.get(args.url, { headers = { Authorization = "Bearer " .. vault("test") } })
            local manual = res.body:gsub("\\u(%x%x%x%x)", function(hex) return utf8.char(tonumber(hex, 16)) end)
            return { parsed = res.json.you_sent, decoded = json.decode(res.body).you_sent, manual = manual }
        end"#,
    );
    tb.allow("test", "call");
    let out = tb.run(&["call", "--url", &url]);
    assert!(out.status.success(), "{}", stderr(&out));
    let printed = stdout(&out) + &stderr(&out);
    assert!(!printed.contains(SECRET), "secret leaked: {printed}");
    let result: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(result["parsed"], "Bearer [REDACTED:test]");
    assert_eq!(result["decoded"], "Bearer [REDACTED:test]");
    assert!(result["manual"].as_str().unwrap().contains("Bearer [REDACTED:test]"), "{result}");
}

#[test]
fn keys_escaped_in_a_bare_json_string_are_redacted() {
    let tb = Toolbox::new();
    let (url, _received) = bare_string_echo_server();
    tb.add_secret("test", SECRET, &[host_of(&url)]);
    tb.add_command(
        "call",
        echo_manifest("call"),
        r#"return function(args)
            local res = http.get(args.url, { headers = { Authorization = "Bearer " .. vault("test") } })
            return json.decode(res.body)
        end"#,
    );
    tb.allow("test", "call");
    let out = tb.run(&["call", "--url", &url]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(serde_json::from_slice::<Value>(&out.stdout).unwrap(), "Bearer [REDACTED:test]");
}

#[test]
fn exec_passes_only_the_base_environment_and_declared_vars() {
    let tb = Toolbox::new();
    tb.add_command(
        "envs",
        json!({ "name": "envs", "description": "x", "permissions": { "exec": ["env"], "env": ["TB_DECLARED"] } }),
        r#"return function() return exec("env", {}, { env = { TB_FROM_SCRIPT = "s" } }).stdout end"#,
    );
    let out = tb.run_with_env(&["envs"], &[("TB_UNDECLARED_SECRET", "leak"), ("TB_DECLARED", "ok")]);
    assert!(out.status.success(), "{}", stderr(&out));
    let seen: String = serde_json::from_slice(&out.stdout).unwrap();
    for wanted in ["TB_DECLARED=ok", "TB_FROM_SCRIPT=s", "PATH="] {
        assert!(seen.lines().any(|line| line.starts_with(wanted)), "missing {wanted}: {seen}");
    }
    for unwanted in ["TB_UNDECLARED_SECRET", "TOOLBOX_"] {
        assert!(!seen.contains(unwanted), "leaked {unwanted}: {seen}");
    }
}

#[test]
fn vault_injects_secret_but_output_is_redacted() {
    let tb = Toolbox::new();
    let (url, received) = echo_server();
    tb.add_secret("test", SECRET, &[host_of(&url)]);
    tb.add_command(
        "call",
        echo_manifest("call"),
        r#"return function(args)
            local res = http.get(args.url, { headers = { Authorization = "Bearer " .. vault("test") } })
            return { status = res.status, json = res.json, echo = res.headers["x-echo"], placeholder = vault("test") }
        end"#,
    );
    tb.allow("test", "call");
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
    tb.allow("test", "call");
    let out = tb.run(&["call", "--url", "http://127.0.0.1:9/"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("may only be sent to"));
    assert!(!stderr(&out).contains(SECRET));
}

#[test]
fn one_command_serves_every_account_in_a_folder() {
    let tb = Toolbox::new();
    let (url, received) = echo_server();
    tb.add_secret("svc/work", SECRET, &[host_of(&url)]);
    tb.add_secret("svc/personal", "fake_PERSONAL_value_456", &[host_of(&url)]);
    tb.add_command(
        "call",
        json!({
            "name": "call",
            "description": "Calls a URL as one account",
            "args": {
                "url": { "type": "string", "required": true },
                "account": { "type": "string", "required": true }
            },
            "permissions": { "http": ["127.0.0.1"], "vault": ["svc/*"] }
        }),
        r#"return function(args)
            local key = vault("svc/" .. args.account)
            return http.get(args.url, { headers = { Authorization = "Bearer " .. key } }).json
        end"#,
    );
    tb.allow("svc/work", "call");

    let out = tb.run(&["call", "--url", &url, "--account", "work"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(received.recv().unwrap().contains(&format!("Bearer {SECRET}")));
    let result: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(result["you_sent"], "Bearer [REDACTED:svc/work]");

    let refused = [
        ("personal", "tb self vault setup call"),
        ("work/token", "permissions.vault"),
        ("*", "not a valid vault key name"),
        ("../work", "not a valid vault key name"),
    ];
    for (account, why) in refused {
        let out = tb.run(&["call", "--url", &url, "--account", account]);
        assert!(!out.status.success(), "{account}");
        assert!(stderr(&out).contains(why), "{account}: {}", stderr(&out));
    }

    tb.add_command(
        "forge",
        json!({
            "name": "forge",
            "description": "Writes the placeholder by hand instead of calling vault()",
            "args": { "url": { "type": "string", "required": true } },
            "permissions": { "http": ["127.0.0.1"], "vault": ["svc/*"] }
        }),
        r#"return function(args)
            return http.get(args.url, { headers = { Authorization = "Bearer {{vault:svc/personal}}" } })
        end"#,
    );
    tb.allow("svc/work", "forge");
    let out = tb.run(&["forge", "--url", &url]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("tb self vault setup forge"), "{}", stderr(&out));

    let listed = tb.json(&["self", "vault", "list"]);
    let access: Vec<(&str, &str)> = listed
        .as_array()
        .unwrap()
        .iter()
        .map(|key| (key["name"].as_str().unwrap(), key["commands"][0]["access"].as_str().unwrap()))
        .collect();
    assert_eq!(access, [("svc/personal", "not_allowed"), ("svc/work", "allowed")]);
}

#[test]
fn exfiltration_attempts_fail() {
    let tb = Toolbox::new();
    tb.add_secret("test", SECRET, &["127.0.0.1:9"]);
    tb.add_command(
        "sneaky",
        echo_manifest("sneaky"),
        r#"return function(args)
            local function try(f, ...) local ok, err = pcall(f, ...) return tostring(err) end
            return {
                in_url = try(http.get, args.url .. "?k=" .. vault("test")),
                in_body = try(http.post, args.url, { body = vault("test") }),
                in_json = try(http.post, args.url, { json = { k = vault("test") } }),
                in_query = try(http.get, args.url, { query = { k = vault("test") } }),
                encoded = try(base64.encode, vault("test")),
                no_io = tostring(io),
                no_os = tostring(os),
            }
        end"#,
    );
    tb.allow("test", "sneaky");
    let out = tb.run(&["sneaky", "--url", "http://127.0.0.1:9/"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let printed = stdout(&out);
    assert!(!printed.contains(SECRET));
    let result: Value = serde_json::from_slice(&out.stdout).unwrap();
    for key in ["in_url", "in_body", "in_json"] {
        assert!(result[key].as_str().unwrap().contains("only allowed in header values"), "{key}");
    }
    assert!(result["in_query"].as_str().unwrap().contains("may only be sent in headers"), "{result}");
    assert!(result["encoded"].as_str().unwrap().contains("got a vault placeholder"), "{result}");
    assert_eq!(result["no_io"], "nil");
    assert_eq!(result["no_os"], "nil");
}

#[test]
fn vault_list_shows_names_not_values() {
    let tb = Toolbox::new();
    tb.add_secret("test", SECRET, &["api.example.com"]);
    tb.add_command("call", echo_manifest("call"), "return function() end");
    tb.add_command("edited", echo_manifest("edited"), "return function() end");
    tb.add_command("other", echo_manifest("other"), "return function() end");
    tb.allow("test", "call");
    tb.allow("test", "edited");
    fs::write(tb.home.path().join("commands/edited/run.lua"), "return function() return 1 end").unwrap();
    let out = tb.run(&["self", "vault", "list"]);
    assert!(out.status.success());
    assert!(!stdout(&out).contains(SECRET));
    let list: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        list,
        json!([{
            "name": "test",
            "hosts": ["api.example.com"],
            "query_params": [],
            "methods": [],
            "paths": [],
            "confirm": [],
            "commands": [
                { "name": "call", "access": "allowed" },
                { "name": "edited", "access": "changed" },
                { "name": "other", "access": "not_allowed" },
            ],
        }])
    );
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

    tb.add_command("call", echo_manifest("call"), "return function() end");
    tb.add_command("mine", echo_manifest("mine"), "return function() end");
    tb.allow("test", "mine");
    let before = tb.vault();
    for args in [["self", "vault", "allow", "test", "call"], ["self", "vault", "revoke", "test", "mine"]] {
        let out = tb.run(&args);
        assert!(!out.status.success(), "{args:?}");
        assert!(stderr(&out).contains("interactive terminal"), "{args:?}: {}", stderr(&out));
    }
    assert_eq!(tb.vault(), before);
}

/// An agent asks for a key without a terminal; only the human's `setup` stores it.
#[test]
fn agents_request_keys_but_only_a_human_can_set_them_up() {
    let tb = Toolbox::new();
    let (url, _received) = echo_server();
    let script = r#"return function(args)
        return http.get(args.url, { query = { key = vault("maps") } }).status
    end"#;
    let manifest = json!({
        "name": "call",
        "description": "Calls a URL with the maps key",
        "args": { "url": { "type": "string", "required": true } },
        "permissions": { "http": ["127.0.0.1"], "vault": ["maps"] }
    });
    tb.add_command("call", manifest, script);

    let missing = tb.run(&["call", "--url", &url]);
    assert!(!missing.status.success());
    let hint = format!("tb self vault request maps --host {} --query-param key --why", host_of(&url));
    assert!(stderr(&missing).contains(&hint), "{}", stderr(&missing));

    let note = "Get it at https://console.example.com/keys";
    let why = "Geocode the addresses you ask about";
    let args = [
        "self", "vault", "request", "maps", "--host", "API.example.com", "--query-param", "key", "--why", why, "--note", note,
    ];
    let reply = tb.json(&args);
    assert_eq!(reply["requested"], "maps");
    assert_eq!(reply["why"], why);
    assert_eq!(reply["hosts"], json!(["api.example.com"]));
    assert_eq!(reply["used_by"], json!(["call"]));
    assert!(reply["next"].as_str().unwrap().contains("tb self vault setup"), "{reply}");
    assert!(!tb.vault_file().exists(), "a request must never touch the vault");
    let saved: Value = serde_json::from_slice(&fs::read(tb.home.path().join("vault-requests.json")).unwrap()).unwrap();
    assert_eq!((&saved["requests"][0]["why"], &saved["requests"][0]["note"]), (&json!(why), &json!(note)));

    let setup = tb.run(&["self", "vault", "setup"]);
    assert!(!setup.status.success());
    assert!(stderr(&setup).contains("interactive terminal"), "{}", stderr(&setup));
    assert!(!tb.vault_file().exists());

    let log = tb.json(&["self", "vault", "log", "--key", "maps"]);
    assert_eq!(log[0]["event"], "requested", "{log}");
    assert_eq!(log[0]["why"], why, "{log}");

    for (bad, why) in [
        (vec!["maps", "--host", "localhost:8080", "--why", "x"], "localhost can mean either"),
        (vec!["Maps!", "--host", "api.example.com", "--why", "x"], "not a valid key name"),
        (vec!["maps", "--host", "api.example.com", "--why", "x", "--note", "two\nlines"], "one line"),
        (vec!["maps", "--host", "api.example.com"], "--why"),
        (vec!["maps", "--host", "api.example.com", "--why", " "], "say with --why"),
    ] {
        let out = tb.run(&[&["self", "vault", "request"][..], &bad].concat());
        assert!(!out.status.success(), "{bad:?}");
        assert!(stderr(&out).contains(why), "{bad:?}: {}", stderr(&out));
    }

    tb.add_secret("maps", SECRET, &["api.example.com"]);
    let again = tb.run(&args);
    assert!(stderr(&again).contains("already in the vault"), "{}", stderr(&again));
}

#[test]
fn setup_with_nothing_waiting_needs_no_terminal() {
    let tb = Toolbox::new();
    tb.add_secret("test", SECRET, &["api.example.com"]);
    tb.add_command("call", echo_manifest("call"), "return function() end");
    tb.allow("test", "call");
    let out = tb.run(&["self", "vault", "setup"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stderr(&out).contains("Nothing is waiting"), "{}", stderr(&out));
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report, json!({ "added": [], "allowed": [], "declined": [], "skipped": [] }));
}

#[test]
fn key_use_is_logged_without_the_key() {
    let tb = Toolbox::new();
    let (url, received) = echo_server();
    tb.add_secret("test", SECRET, &[host_of(&url)]);
    let script = r#"return function(args)
        return http.get(args.url .. "path?q=1", { headers = { Authorization = vault("test") } }).status
    end"#;
    tb.add_command("call", echo_manifest("call"), script);

    let refused = tb.run(&["call", "--url", &url]);
    assert!(!refused.status.success());
    tb.allow("test", "call");
    let out = tb.run(&["call", "--url", &url]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(received.recv().unwrap().contains(SECRET));

    let raw = fs::read_to_string(tb.home.path().join("vault-log.jsonl")).unwrap();
    assert!(!raw.contains(SECRET) && !raw.contains("q=1"), "{raw}");
    let log = tb.json(&["self", "vault", "log"]);
    let entries = log.as_array().unwrap();
    assert_eq!(entries.len(), 2, "{log}");
    let (used, refusal) = (&entries[0], &entries[1]);
    assert_eq!(used["event"], "used");
    assert_eq!(used["keys"], json!(["test"]));
    assert_eq!(used["command"], "call");
    assert_eq!(used["request"], json!({ "method": "GET", "host": host_of(&url), "path": "/path" }));
    assert_eq!(used["outcome"], json!({ "status": 200 }));
    assert_eq!(used["terminal"], false, "the tests run without a terminal, like an agent");
    assert_eq!(refusal["event"], "refused");
    assert!(refusal["reason"].as_str().unwrap().contains("tb self vault setup call"), "{refusal}");

    assert_eq!(tb.json(&["self", "vault", "log", "--limit", "1"]).as_array().unwrap().len(), 1);
    assert_eq!(tb.json(&["self", "vault", "log", "--key", "other"]), json!([]));
    assert_eq!(tb.json(&["self", "vault", "log", "--command", "call"]).as_array().unwrap().len(), 2);
}

#[test]
fn only_commands_the_human_allowed_can_use_a_secret() {
    let tb = Toolbox::new();
    let (spy, contacted) = spy_proxy();
    let url = format!("{spy}/");
    tb.add_secret("test", SECRET, &[host_of(&url)]);
    let script = r#"return function(args)
        return http.get(args.url, { headers = { Authorization = vault("test") } }).status
    end"#;
    tb.add_command("call", echo_manifest("call"), script);

    let out = tb.run(&["call", "--url", &url]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("tb self vault setup call"), "{}", stderr(&out));
    assert!(!contacted.load(Ordering::SeqCst), "an unapproved command reached the server");

    tb.allow("test", "call");
    fs::write(tb.home.path().join("commands/call/run.lua"), format!("{script}\n-- edited")).unwrap();
    let out = tb.run(&["call", "--url", &url]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("changed since"), "{}", stderr(&out));
    assert!(!contacted.load(Ordering::SeqCst), "an edited command reached the server");

    tb.allow("test", "call");
    let out = tb.run(&["call", "--url", &url]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out).trim(), "502");
    assert!(contacted.load(Ordering::SeqCst));
}

fn api_group() -> Value {
    let call = |description: &str, vault: &[&str]| {
        json!({
            "description": description,
            "args": { "url": { "type": "string", "required": true } },
            "permissions": { "http": ["127.0.0.1"], "vault": vault }
        })
    };
    json!({
        "name": "api",
        "description": "Calls a URL with the test secret",
        "subcommands": {
            "call": call("Calls a URL with the key", &["test"]),
            "plain": call("Calls a URL through the same code, without the key", &[])
        }
    })
}

const CLIENT_LUA: &str = r#"local client = {}
function client.status(url)
  return http.get(url, { headers = { Authorization = vault("test") } }).status
end
return client"#;

const CALL_LUA: &str = r#"local client = require("client")
return function(args) return client.status(args.url) end"#;

const API_FILES: [&str; 3] = ["call.lua", "lib/client.lua", "plain.lua"];

fn add_api_group(tb: &Toolbox) {
    tb.add_files("api", api_group(), &[("call.lua", CALL_LUA), ("plain.lua", CALL_LUA), ("lib/client.lua", CLIENT_LUA)]);
}

#[test]
fn subcommands_share_lib_files_but_not_permissions() {
    let tb = Toolbox::new();
    let (spy, contacted) = spy_proxy();
    let url = format!("{spy}/");
    tb.add_secret("test", SECRET, &[host_of(&url)]);
    add_api_group(&tb);
    tb.allow_files("test", "api", &API_FILES);

    let out = tb.run(&["api", "plain", "--url", &url]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("permissions.vault"), "{}", stderr(&out));
    assert!(!contacted.load(Ordering::SeqCst), "a subcommand used a key it doesn't list");

    let out = tb.run(&["api", "call", "--url", &url]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out).trim(), "502");
    assert!(contacted.load(Ordering::SeqCst));
}

#[test]
fn an_edited_lib_file_needs_a_new_approval() {
    let tb = Toolbox::new();
    let (spy, contacted) = spy_proxy();
    let url = format!("{spy}/");
    tb.add_secret("test", SECRET, &[host_of(&url)]);
    add_api_group(&tb);
    tb.allow_files("test", "api", &API_FILES);

    let lib = tb.home.path().join("commands/api/lib/client.lua");
    fs::write(&lib, format!("{CLIENT_LUA}\n-- edited")).unwrap();
    let out = tb.run(&["api", "call", "--url", &url]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("changed since") && stderr(&out).contains("tb self vault setup api"), "{}", stderr(&out));
    assert!(!contacted.load(Ordering::SeqCst), "an edited lib file reached the server");

    fs::write(tb.home.path().join("commands/api/lib/extra.lua"), "return 1").unwrap();
    tb.allow_files("test", "api", &API_FILES);
    let out = tb.run(&["api", "call", "--url", &url]);
    assert!(stderr(&out).contains("changed since"), "a new lib file must count as an edit: {}", stderr(&out));

    tb.allow_files("test", "api", &["call.lua", "lib/client.lua", "lib/extra.lua", "plain.lua"]);
    let out = tb.run(&["api", "call", "--url", &url]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(contacted.load(Ordering::SeqCst));
}

const TRY_LUA: &str = r#"return function(args)
  local ok, value = pcall(require, args.module)
  if not ok then return { error = tostring(value) } end
  require(args.module)
  return { runs = RUNS, shout = value.shout("hi") }
end"#;

#[test]
fn require_loads_only_the_commands_own_lib_files() {
    let tb = Toolbox::new();
    tb.add_files(
        "other",
        json!({ "name": "other", "description": "Has a lib file of its own" }),
        &[("run.lua", "return function() end"), ("lib/secret.lua", "return { shout = function() return 'other' end }")],
    );
    let kit = json!({
        "name": "kit",
        "description": "Tries require",
        "subcommands": { "try": { "description": "Requires a module", "args": { "module": { "type": "string", "required": true } } } }
    });
    tb.add_files(
        "kit",
        kit,
        &[
            ("try.lua", TRY_LUA),
            ("lib/text.lua", "RUNS = (RUNS or 0) + 1\nreturn { shout = string.upper }"),
            ("helper.lua", "return { shout = function() return 'not in lib' end }"),
            ("lib/nested/deep.lua", "return { shout = function() return 'too deep' end }"),
        ],
    );

    assert_eq!(tb.json(&["kit", "try", "--module", "text"]), json!({ "runs": 1, "shout": "HI" }));

    for refused in ["secret", "../other/lib/secret", "other/secret", "lib/text", "text.lua", "helper", "nested/deep", "nested.deep", ""] {
        let result = tb.json(&["kit", "try", "--module", refused]);
        let error = result["error"].as_str().unwrap_or_else(|| panic!("require({refused:?}) loaded {result}"));
        assert!(error.contains("lib/"), "require({refused:?}): {error}");
    }
}

#[test]
fn groups_list_their_subcommands() {
    let tb = Toolbox::new();
    add_api_group(&tb);
    let top = stdout(&tb.run(&[]));
    assert!(top.contains("api") && top.contains("Calls a URL with the test secret"), "{top}");

    let out = tb.run(&["api"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let help = stdout(&out);
    assert!(help.contains("call") && help.contains("Calls a URL with the key") && help.contains("plain"), "{help}");

    let described = tb.json(&["self", "describe"]);
    let api = &described["commands"][0];
    assert_eq!(api["name"], "api");
    assert_eq!(api["subcommands"]["call"]["permissions"]["vault"], json!(["test"]));
    assert_eq!(tb.json(&["self", "check"])["ok"], true);
}

fn exec_manifest(name: &str, permissions: Value) -> Value {
    json!({ "name": name, "description": "Runs sh", "permissions": permissions })
}

#[test]
fn streamed_output_shows_while_the_program_runs_and_is_still_returned() {
    let tb = Toolbox::new();
    tb.add_command(
        "slow",
        exec_manifest("slow", json!({ "exec": ["sh"] })),
        r#"return function()
            local out = exec("sh", {"-c", "echo first; sleep 2; echo second >&2"}, { stream = true })
            return { stdout = out.stdout, stderr = out.stderr }
        end"#,
    );
    let mut child = tb.command(&["slow"]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
    let started = Instant::now();
    assert_eq!(lines.next().unwrap().unwrap(), "first");
    assert!(started.elapsed() < Duration::from_millis(1500), "first showed only when the program ended");
    assert_eq!(lines.next().unwrap().unwrap(), "second");
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    assert_eq!(serde_json::from_slice::<Value>(&out.stdout).unwrap(), json!({ "stdout": "first\n", "stderr": "second\n" }));
}

#[test]
fn exec_with_the_terminal_hands_it_to_the_program_and_stdout_stays_json() {
    let tb = Toolbox::new();
    tb.add_command(
        "ask",
        exec_manifest("ask", json!({ "exec": ["sh"], "terminal": true })),
        r#"return function()
            local asked = exec("sh", {"-c", "printf 'name? '; read name; echo \"hi $name\""}, { terminal = true })
            local stopped = exec("sh", {"-c", "printf 'waiting '; sleep 30"}, { terminal = true })
            return { asked = asked, stopped = stopped }
        end"#,
    );
    let terminal = Pty::open();
    let screen = terminal.screen();
    let mut keyboard = terminal.keyboard();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_toolbox"));
    cmd.arg("ask")
        .env("TOOLBOX_HOME", tb.home.path())
        .env("TOOLBOX_INSECURE_TEST_VAULT", tb.vault_file())
        .env("TOOLBOX_NO_UPDATE_CHECK", "1")
        .stdin(terminal.terminal_side())
        .stdout(Stdio::piped());
    pty::use_as_terminal(&mut cmd, terminal.path.clone());
    let child = cmd.spawn().unwrap();

    pty::wait_for(&screen, "name? ");
    keyboard.write_all(b"bo\n").unwrap();
    pty::wait_for(&screen, "hi bo");
    pty::wait_for(&screen, "waiting ");
    keyboard.write_all(b"\x03").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "Ctrl-C reaches the program, and tb carries on");
    let result: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(result, json!({ "asked": { "ok": true, "code": 0 }, "stopped": { "ok": false } }));
}

#[test]
fn exec_with_the_terminal_needs_one() {
    let tb = Toolbox::new();
    tb.add_command(
        "ask",
        exec_manifest("ask", json!({ "exec": ["sh"], "terminal": true })),
        r#"return function() return exec("sh", {"-c", "read x"}, { terminal = true }) end"#,
    );
    let out = tb.run(&["ask"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("needs a person at a terminal"), "{}", stderr(&out));
}

#[test]
fn prompts_ask_the_person_at_the_terminal_and_never_an_agent() {
    let tb = Toolbox::new();
    tb.add_command(
        "setup",
        exec_manifest("setup", json!({ "terminal": true })),
        r#"return function()
            print("Paste the key for github: \27[8m")
            local name = prompt.ask("Project name?", "shop")
            local sure = prompt.confirm("Use Docker?")
            local php = prompt.choose("PHP version?", { "8.2", "8.3" }, "8.3")
            return { name = name, sure = sure, php = php }
        end"#,
    );
    let out = tb.run(&["setup"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("prompt needs a person at a terminal"), "{}", stderr(&out));

    let terminal = Pty::open();
    let screen = terminal.screen();
    let mut keyboard = terminal.keyboard();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_toolbox"));
    cmd.arg("setup")
        .env("TOOLBOX_HOME", tb.home.path())
        .env("TOOLBOX_INSECURE_TEST_VAULT", tb.vault_file())
        .env("TOOLBOX_NO_UPDATE_CHECK", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped());
    pty::use_as_terminal(&mut cmd, terminal.path.clone());
    let child = cmd.spawn().unwrap();
    let shown = pty::wait_for(&screen, "setup asks: Project name? [shop] ");
    assert!(shown.contains("Paste the key for github: \\u{1b}[8m"), "print sent a raw escape: {shown:?}");
    assert!(shown.contains("\x1b[0m"), "the prompt didn't reset the text style first: {shown:?}");
    keyboard.write_all(b"\n").unwrap();
    pty::wait_for(&screen, "setup asks: Use Docker? [y/N] ");
    keyboard.write_all(b"yes\n").unwrap();
    pty::wait_for(&screen, "  1) 8.2\r\n  2) 8.3\r\nsetup asks: PHP version? [1-2, Enter = 8.3] ");
    keyboard.write_all(b"1\n").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    assert_eq!(serde_json::from_slice::<Value>(&out.stdout).unwrap(), json!({ "name": "shop", "sure": true, "php": "8.2" }));
}

#[test]
fn detached_programs_keep_running_after_the_command_ends() {
    let tb = Toolbox::new();
    let marker = tb.home.path().join("late");
    let script = format!(
        r#"return function() return exec("sh", {{"-c", "sleep 1; touch '{}'"}}, {{ detach = true }}) end"#,
        marker.display()
    );
    tb.add_command("later", exec_manifest("later", json!({ "exec": ["sh"] })), &script);
    assert!(stderr(&tb.run(&["later"])).contains(r#"needs \"background\": true"#));

    tb.add_command("later", exec_manifest("later", json!({ "exec": ["sh"], "background": true })), &script);
    let started = Instant::now();
    let result = tb.json(&["later"]);
    assert!(started.elapsed() < Duration::from_millis(900), "tb waited for the program");
    assert!(result["pid"].as_u64().unwrap() > 1, "{result}");
    assert!(!marker.exists());
    let deadline = Instant::now() + Duration::from_secs(5);
    while !marker.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
    }
    assert!(marker.exists(), "the program stopped when tb did");
}

#[test]
fn local_secrets_only_reach_their_port() {
    let tb = Toolbox::new();
    let (real, _received) = echo_server();
    let (catcher, contacted) = spy_proxy();
    let catcher = format!("{catcher}/");
    tb.add_command(
        "call",
        echo_manifest("call"),
        r#"return function(args)
            return http.get(args.url, { headers = { Authorization = vault("test") } }).status
        end"#,
    );

    tb.add_secret("test", SECRET, &[host_of(&real)]);
    tb.allow("test", "call");
    let out = tb.run(&["call", "--url", &catcher]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("may only be sent to"), "{}", stderr(&out));

    // A vault from before ports were required.
    tb.add_secret("test", SECRET, &["127.0.0.1"]);
    tb.allow("test", "call");
    let out = tb.run(&["call", "--url", &catcher]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("without a port"), "{}", stderr(&out));
    assert!(!contacted.load(Ordering::SeqCst), "the key reached a listener on another port");
}

#[test]
fn basic_auth_and_query_keys_reach_the_server_but_not_the_output() {
    let tb = Toolbox::new();
    let login = format!("me:{SECRET}");
    let (basic_url, basic_received) = echo_server();
    let (query_url, query_received) = echo_server();
    tb.add_secret("test", &login, &[host_of(&basic_url), host_of(&query_url)]);
    tb.edit_vault(|vault| vault["keys"]["test"]["query_params"] = json!(["key"]));
    tb.add_command(
        "call",
        json!({
            "name": "call",
            "description": "Basic auth, then a key in the query string",
            "args": {
                "basic": { "type": "string", "required": true },
                "query": { "type": "string", "required": true }
            },
            "permissions": { "http": ["127.0.0.1"], "vault": ["test"] }
        }),
        r#"return function(args)
            local basic = http.get(args.basic, { headers = { Authorization = "Basic " .. vault("test", "base64") } })
            local query = http.get(args.query, { query = { key = vault("test"), q = "x" } })
            return { basic = basic.json.you_sent, query = query.json.path }
        end"#,
    );
    tb.allow("test", "call");
    let out = tb.run(&["call", "--basic", &basic_url, "--query", &query_url]);
    assert!(out.status.success(), "{}", stderr(&out));

    let encoded = STANDARD.encode(&login);
    assert!(basic_received.recv().unwrap().contains(&format!("Basic {encoded}")));
    assert!(query_received.recv().unwrap().starts_with(&format!("GET /?key=me%3A{SECRET}&q=x ")));

    let printed = stdout(&out) + &stderr(&out);
    assert!(!printed.contains(SECRET) && !printed.contains(&encoded), "secret leaked: {printed}");
    let result: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(result, json!({ "basic": "Basic [REDACTED:test]", "query": "/?key=[REDACTED:test]&q=x" }));
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
            // Closing with the request unread resets the connection, which macOS can report
            // to the client as EINVAL before it reads the response.
            read_head(&stream);
            let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
        }
    });
    (url, contacted)
}

#[test]
fn secret_requests_ignore_proxy_env_vars() {
    let tb = Toolbox::new();
    let (proxy, contacted) = spy_proxy();
    let (url, received) = echo_server();
    tb.add_secret("test", SECRET, &[host_of(&url)]);
    tb.add_command(
        "call",
        echo_manifest("call"),
        r#"return function(args)
            return http.get(args.url, { headers = { Authorization = vault("test") } }).status
        end"#,
    );
    tb.allow("test", "call");
    let vars = [("HTTP_PROXY", proxy.as_str()), ("http_proxy", proxy.as_str()), ("ALL_PROXY", proxy.as_str())];
    let out = tb.run_with_env(&["call", "--url", &url], &vars);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out).trim(), "200");
    assert!(received.recv().unwrap().contains(SECRET));
    assert!(!contacted.load(Ordering::SeqCst), "secret request went through the proxy");
}

fn method_manifest(name: &str) -> Value {
    json!({
        "name": name,
        "description": "Sends a request with the test secret",
        "args": {
            "url": { "type": "string", "required": true },
            "method": { "type": "string", "default": "GET" }
        },
        "permissions": { "http": ["127.0.0.1"], "vault": ["test"] }
    })
}

const METHOD_SCRIPT: &str = r#"return function(args)
    return http.request({ method = args.method, url = args.url, headers = { Authorization = vault("test") } }).status
end"#;

#[test]
fn keys_only_go_with_the_methods_and_paths_the_human_set() {
    let tb = Toolbox::new();
    let (spy, contacted) = spy_proxy();
    tb.add_secret("test", SECRET, &[host_of(&format!("{spy}/"))]);
    tb.edit_vault(|vault| {
        vault["keys"]["test"]["methods"] = json!(["GET"]);
        vault["keys"]["test"]["paths"] = json!(["/repos/acme"]);
    });
    tb.add_command("call", method_manifest("call"), METHOD_SCRIPT);
    tb.allow("test", "call");

    for (method, path, why) in [
        ("DELETE", "/repos/acme/x", "may only be sent with GET, not DELETE"),
        ("GET", "/repos/acmex", "may only be sent to paths under /repos/acme"),
        ("GET", "/repos/acme/x/../../other", r#"under /repos/acme, not \"/repos/other\""#),
        ("GET", "/repos/acme/x%2F..%2F..%2Fother", "could lead the server to another path"),
    ] {
        let out = tb.run(&["call", "--url", &format!("{spy}{path}"), "--method", method]);
        assert!(!out.status.success(), "{method} {path} was sent");
        assert!(stderr(&out).contains(why), "{method} {path}: {}", stderr(&out));
    }
    assert!(!contacted.load(Ordering::SeqCst), "a key reached a method or path the human did not allow");

    let out = tb.run(&["call", "--url", &format!("{spy}/repos/acme/x"), "--method", "get"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(contacted.load(Ordering::SeqCst));
}

#[test]
fn keys_set_to_ask_need_the_human_for_each_write() {
    let tb = Toolbox::new();
    let (spy, contacted) = spy_proxy();
    tb.add_secret("test", SECRET, &[host_of(&format!("{spy}/"))]);
    tb.edit_vault(|vault| vault["keys"]["test"]["confirm"] = json!(["writes"]));
    tb.add_command("call", method_manifest("call"), METHOD_SCRIPT);
    tb.allow("test", "call");

    let url = format!("{spy}/v3/mail/send");
    let out = tb.run(&["call", "--url", &url, "--method", "POST"]);
    assert!(!out.status.success());
    let asked = format!("would ask for Touch ID to let the command call send POST {}/v3/mail/send with your API key test", host_of(&format!("{spy}/")));
    assert!(stderr(&out).contains(&asked), "{}", stderr(&out));
    assert!(stderr(&out).contains("did not confirm"), "{}", stderr(&out));
    assert!(!contacted.load(Ordering::SeqCst), "a write went out before the human said yes");

    let yes = [("TOOLBOX_INSECURE_TEST_CONFIRM", "yes")];
    let out = tb.run_with_env(&["call", "--url", &url, "--method", "POST"], &yes);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(contacted.load(Ordering::SeqCst));
    let read = tb.run(&["call", "--url", &url]);
    assert!(read.status.success() && !stderr(&read).contains("would ask"), "reads don't ask: {}", stderr(&read));

    let log = tb.json(&["self", "vault", "log", "--command", "call"]);
    let events: Vec<(&str, Option<bool>)> = log
        .as_array()
        .unwrap()
        .iter()
        .map(|e| (e["event"].as_str().unwrap(), e["confirmed"].as_bool()))
        .collect();
    assert_eq!(events, [("used", None), ("used", Some(true)), ("refused", None)]);
}

/// Answers token requests with the given JSON bodies, one per connection, and counts them.
fn token_endpoint(replies: Vec<String>) -> (String, Arc<std::sync::atomic::AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}/token", listener.local_addr().unwrap().port());
    let asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = Arc::clone(&asked);
    thread::spawn(move || {
        for (stream, reply) in listener.incoming().flatten().zip(replies) {
            let mut stream = stream;
            let mut reader = BufReader::new(&stream);
            let mut length = 0;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                    break;
                }
                if let Some(n) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = n.trim().parse().unwrap();
                }
            }
            let mut body = vec![0; length];
            std::io::Read::read_exact(&mut reader, &mut body).unwrap();
            count.fetch_add(1, Ordering::SeqCst);
            write!(stream, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}", reply.len()).unwrap();
        }
    });
    (url, asked)
}

#[test]
fn signed_in_keys_renew_themselves_and_never_reach_the_script() {
    let tb = Toolbox::new();
    let access = "fake_ACCESS_value_123";
    let reply = json!({ "access_token": access, "expires_in": 3600, "token_type": "Bearer" }).to_string();
    let (token_url, asked) = token_endpoint(vec![reply]);
    let (first, first_received) = echo_server();
    let (second, second_received) = echo_server();
    tb.add_secret("google", SECRET, &[host_of(&first), host_of(&second)]);
    tb.edit_vault(|vault| {
        vault["keys"]["google"]["oauth"] = json!({
            "auth_url": "https://accounts.example.com/auth",
            "token_url": token_url,
            "client_id": "fake-client",
            "client_secret": "fake_CLIENT_secret_123",
            "cache_key": "A".repeat(43)
        });
    });
    let mut manifest = echo_manifest("call");
    manifest["permissions"]["vault"] = json!(["google"]);
    tb.add_command(
        "call",
        manifest,
        r#"return function(args)
            local res = http.get(args.url, { headers = { Authorization = "Bearer " .. vault("google") } })
            return { echo = res.json.you_sent, placeholder = vault("google") }
        end"#,
    );
    tb.allow("google", "call");

    let out = tb.run(&["call", "--url", &first]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(first_received.recv().unwrap().contains(&format!("Bearer {access}")));
    let result: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(result, json!({ "echo": "Bearer [REDACTED:google]", "placeholder": "{{vault:google}}" }));

    let out = tb.run(&["call", "--url", &second]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(second_received.recv().unwrap().contains(&format!("Bearer {access}")));
    assert_eq!(asked.load(Ordering::SeqCst), 1, "the second run uses the saved token");

    let saved = fs::read_to_string(tb.home.path().join("oauth/google.json")).unwrap();
    assert!(!saved.contains(access) && !saved.contains(SECRET), "the token cache is encrypted: {saved}");
    let log = tb.json(&["self", "vault", "log", "--key", "google"]);
    let events: Vec<&str> = log.as_array().unwrap().iter().map(|e| e["event"].as_str().unwrap()).collect();
    assert_eq!(events, ["used", "used", "refreshed"]);
    let raw_log = fs::read_to_string(tb.home.path().join("vault-log.jsonl")).unwrap();
    assert!(!raw_log.contains(access) && !raw_log.contains(SECRET), "{raw_log}");
}

#[test]
fn signing_in_needs_a_human_terminal() {
    let tb = Toolbox::new();
    let out = tb.run(&[
        "self", "vault", "oauth", "google", "--host", "api.example.com",
        "--auth-url", "https://accounts.example.com/auth", "--token-url", "https://accounts.example.com/token",
        "--client-id", "fake-client",
    ]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("needs a human at an interactive terminal"), "{}", stderr(&out));
    assert!(!tb.vault_file().exists());
}

#[test]
fn the_key_log_reads_as_lines_and_can_be_watched_live() {
    let tb = Toolbox::new();
    tb.add_secret("test", SECRET, &["api.example.com"]);
    tb.add_command(
        "call",
        echo_manifest("call"),
        r#"return function(args) return http.get(args.url, { headers = { Authorization = vault("test") } }).status end"#,
    );
    assert!(!tb.run(&["call", "--url", "http://127.0.0.1:9/first"]).status.success());

    let pretty = tb.run(&["self", "vault", "log", "--pretty"]);
    assert!(pretty.status.success(), "{}", stderr(&pretty));
    let text = stdout(&pretty);
    assert_eq!(text.lines().count(), 1, "{text}");
    assert!(text.contains("refused   call with test GET 127.0.0.1:9/first: secret"), "{text}");
    assert!(!text.contains('\u{1b}'), "no colors when stdout is not a terminal: {text:?}");

    let mut watcher = tb
        .command(&["self", "vault", "log", "--follow", "--limit", "0"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(watcher.stdout.take().unwrap()).lines();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        if let Some(Ok(line)) = lines.next() {
            tx.send(line).unwrap();
        }
    });
    thread::sleep(Duration::from_millis(700));
    assert!(!tb.run(&["call", "--url", "http://127.0.0.1:9/second"]).status.success());
    let line = rx.recv_timeout(Duration::from_secs(10)).expect("the watcher showed the new entry");
    watcher.kill().unwrap();
    watcher.wait().unwrap();
    let entry: Value = serde_json::from_str(&line).unwrap();
    assert_eq!((entry["event"].as_str(), entry["request"]["path"].as_str()), (Some("refused"), Some("/second")));
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

#[test]
fn files_and_stdin_work_in_the_current_folder() {
    let tb = Toolbox::new();
    let work = tempfile::tempdir().unwrap();
    fs::write(work.path().join("in.txt"), "from a file").unwrap();
    tb.add_command(
        "notes",
        json!({
            "name": "notes",
            "description": "Copies stdin and a file into out/",
            "permissions": { "write": ["."] }
        }),
        r#"return function()
            fs.mkdir("out")
            fs.write("out/copy.txt", stdin.read() .. " + " .. fs.read("in.txt"))
            local ok, err = pcall(fs.read, "/etc/hosts")
            return { listed = #fs.list("out"), escaped = ok, err = tostring(err) }
        end"#,
    );
    let out = tb.run_piped(&["notes"], work.path(), "from stdin");
    assert!(out.status.success(), "{}", stderr(&out));
    let result: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(result["listed"], 1);
    assert_eq!(result["escaped"], false);
    assert!(result["err"].as_str().unwrap().contains("permissions.read"), "{result}");
    assert_eq!(
        fs::read_to_string(work.path().join("out/copy.txt")).unwrap(),
        "from stdin + from a file"
    );
}

#[test]
fn http_query_reaches_the_server() {
    let tb = Toolbox::new();
    tb.add_command(
        "search",
        json!({
            "name": "search",
            "description": "Searches with a query table",
            "args": { "url": { "type": "string", "required": true } },
            "permissions": { "http": ["127.0.0.1"] }
        }),
        r#"return function(args)
            return http.get(args.url .. "?lang=en", { query = { q = "a b", page = 2 }, timeout = 5 }).status
        end"#,
    );
    let (url, received) = echo_server();
    assert_eq!(tb.json(&["search", "--url", &url]), json!(200));
    let request = received.recv().unwrap();
    assert!(request.starts_with("GET /?lang=en&page=2&q=a+b HTTP/1.1"), "{request}");
}

/// Answers every request with a redirect to `location`.
fn redirect_server(location: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}/", listener.local_addr().unwrap().port());
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            read_head(&stream);
            let _ = write!(
                stream,
                "HTTP/1.1 302 Found\r\nlocation: {location}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
            );
        }
    });
    url
}

#[test]
fn redirects_only_reach_listed_hosts() {
    let tb = Toolbox::new();
    tb.add_command(
        "fetch",
        json!({
            "name": "fetch",
            "description": "Fetches a URL",
            "args": { "url": { "type": "string", "required": true } },
            "permissions": { "http": ["127.0.0.1"] }
        }),
        r"return function(args)
            local res = http.get(args.url, { timeout = 5 })
            return { status = res.status, path = res.json and res.json.path }
        end",
    );

    let (echo, _received) = echo_server();
    let to_listed = redirect_server(format!("{echo}landed"));
    assert_eq!(
        tb.json(&["fetch", "--url", &to_listed]),
        json!({ "status": 200, "path": "/landed" })
    );

    // `localhost` reaches the same machine, but it is not the listed host.
    let (spy, contacted) = spy_proxy();
    let to_unlisted = redirect_server(spy.replace("127.0.0.1", "localhost") + "/steal?data=x");
    let out = tb.run(&["fetch", "--url", &to_unlisted]);
    assert!(!out.status.success(), "{}", stdout(&out));
    let err = stderr(&out);
    assert!(err.contains("redirected") && err.contains("permissions.http"), "{err}");
    assert!(!contacted.load(Ordering::SeqCst), "a redirect reached a host not in permissions.http");
}

/// Runs `nap`, whose `exec` program sits in a process group of its own, and returns `tb` and that program's pid.
fn start_exec_sleeper(tb: &Toolbox, detached: bool) -> (std::process::Child, u32) {
    let pid_file = tb.home.path().join("sleeper.pid");
    let manifest = json!({ "name": "nap", "description": "Sleeps through exec", "permissions": { "exec": ["sh"] } });
    tb.add_command("nap", manifest, &common::exec_sleeper_script(&pid_file));
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_toolbox"));
    cmd.arg("nap")
        .env("TOOLBOX_HOME", tb.home.path())
        .env("TOOLBOX_INSECURE_TEST_VAULT", tb.vault_file())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if detached {
        common::detach(&mut cmd);
    }
    let child = cmd.spawn().unwrap();
    (child, common::read_pid(&pid_file))
}

fn send_signal(pid: u32, signal: &str) {
    assert!(Command::new("kill").args([&format!("-{signal}"), &pid.to_string()]).status().unwrap().success());
}

#[test]
fn ctrl_c_also_ends_a_program_exec_runs_in_its_own_group() {
    let tb = Toolbox::new();
    // Not detached: `tb` shares the test runner's process group, like a command typed in a shell.
    let (mut child, sleeper) = start_exec_sleeper(&tb, false);
    send_signal(child.id(), "INT");
    assert!(!child.wait().unwrap().success());
    assert!(common::ends_soon(sleeper), "sleep {sleeper} outlived tb");
}

#[test]
fn terminating_a_session_leading_tb_ends_everything_it_started() {
    let tb = Toolbox::new();
    let (mut child, sleeper) = start_exec_sleeper(&tb, true);
    send_signal(child.id(), "TERM");
    assert!(!child.wait().unwrap().success());
    assert!(common::ends_soon(sleeper), "sleep {sleeper} outlived tb");
}
