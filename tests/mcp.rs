//! End-to-end tests for `tb self mcp`: the real binary as an MCP server over stdio.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tempfile::TempDir;

const WAIT: Duration = Duration::from_secs(15);

struct Server {
    home: TempDir,
    child: Child,
    /// `None` once closed, which is how a client says goodbye.
    input: Option<ChildStdin>,
    messages: Receiver<Value>,
    /// Messages read while waiting for a different one.
    unclaimed: Vec<Value>,
}

impl Server {
    fn start() -> Self {
        let home = tempfile::tempdir().unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_toolbox"));
        cmd.args(["self", "mcp"])
            .env("TOOLBOX_HOME", home.path())
            .env("TOOLBOX_INSECURE_TEST_VAULT", home.path().join("test-vault.json"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        // Detach from any controlling terminal, like an MCP client's child process.
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        let mut child = cmd.spawn().unwrap();
        let input = child.stdin.take();
        let output = BufReader::new(child.stdout.take().unwrap());
        let (tx, messages) = mpsc::channel();
        thread::spawn(move || {
            for line in output.lines().map_while(Result::ok) {
                let message = serde_json::from_str(&line).unwrap_or_else(|_| panic!("not JSON on stdout: {line}"));
                if tx.send(message).is_err() {
                    return;
                }
            }
        });
        Self { home, child, input, messages, unclaimed: Vec::new() }
    }

    /// Starts a server and completes the handshake.
    fn ready() -> Self {
        let mut server = Self::start();
        let init = server.request(0, "initialize", json!({ "protocolVersion": "2025-06-18", "capabilities": {} }));
        assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
        server.notify("notifications/initialized");
        server
    }

    fn add_command(&self, name: &str, args: Value, script: &str, permissions: Value) {
        let dir = self.home.path().join("commands").join(name);
        fs::create_dir_all(&dir).unwrap();
        let manifest = json!({ "name": name, "description": format!("The {name} command"), "args": args, "permissions": permissions });
        fs::write(dir.join("command.json"), manifest.to_string()).unwrap();
        fs::write(dir.join("run.lua"), script).unwrap();
    }

    fn write(&mut self, message: Value) {
        let input = self.input.as_mut().expect("stdin is closed");
        writeln!(input, "{message}").unwrap();
        input.flush().unwrap();
    }

    fn notify(&mut self, method: &str) {
        self.write(json!({ "jsonrpc": "2.0", "method": method }));
    }

    fn send(&mut self, id: i64, method: &str, params: Value) {
        self.write(json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }));
    }

    fn request(&mut self, id: i64, method: &str, params: Value) -> Value {
        self.send(id, method, params);
        self.wait_for(|m| m["id"] == id)
    }

    fn call(&mut self, id: i64, name: &str, arguments: Value) -> Value {
        self.request(id, "tools/call", json!({ "name": name, "arguments": arguments }))
    }

    fn wait_for(&mut self, wanted: impl Fn(&Value) -> bool) -> Value {
        if let Some(i) = self.unclaimed.iter().position(&wanted) {
            return self.unclaimed.remove(i);
        }
        let deadline = Instant::now() + WAIT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let message = self.messages.recv_timeout(left).expect("no matching message from the server");
            if wanted(&message) {
                return message;
            }
            self.unclaimed.push(message);
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn text(reply: &Value, block: usize) -> &str {
    reply["result"]["content"][block]["text"].as_str().unwrap_or_else(|| panic!("no text block {block}: {reply}"))
}

const GREET: &str = r#"return function(args)
    log("greeting " .. args.name)
    local message = "hello " .. args.name
    if args.loud then message = message:upper() end
    return { message = message, times = args.times }
end"#;

fn greet_args() -> Value {
    json!({
        "name": { "type": "string", "required": true, "description": "Who to greet" },
        "loud": { "type": "boolean" },
        "times": { "type": "integer", "default": 1 }
    })
}

#[test]
fn commands_are_listed_and_called_as_tools() {
    let mut server = Server::ready();
    server.add_command("greet", greet_args(), GREET, json!({}));

    let list = server.request(1, "tools/list", json!({}));
    let tools = list["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"], "greet");
    assert_eq!(tools[0]["description"], "The greet command");
    assert_eq!(tools[0]["inputSchema"]["required"], json!(["name"]));
    assert_eq!(tools[0]["inputSchema"]["properties"]["times"], json!({ "type": "integer", "default": 1 }));

    let reply = server.call(2, "greet", json!({ "name": "-bo", "loud": true, "times": 3 }));
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    let result: Value = serde_json::from_str(text(&reply, 0)).unwrap();
    assert_eq!(result, json!({ "message": "HELLO -BO", "times": 3 }));
    assert_eq!(text(&reply, 1), "Log output:\ngreeting -bo");
}

#[test]
fn bad_calls_come_back_as_errors_the_model_can_read() {
    let mut server = Server::ready();
    server.add_command("greet", greet_args(), GREET, json!({}));
    server.add_command("fail", json!({}), r#"return function() error("PR not found") end"#, json!({}));

    let missing = server.call(1, "greet", json!({}));
    assert_eq!(missing["result"]["isError"], true);
    assert!(text(&missing, 0).contains("missing required argument \"name\""), "{missing}");

    let failed = server.call(2, "fail", json!({}));
    assert_eq!(failed["result"]["isError"], true);
    assert!(text(&failed, 0).contains("PR not found"), "{failed}");

    let unknown = server.call(3, "nope", json!({}));
    assert_eq!(unknown["error"]["code"], -32602);

    let builtin = server.call(4, "self", json!({}));
    assert_eq!(builtin["error"]["code"], -32602, "tb self must not be reachable as a tool");
}

#[test]
fn vault_keys_still_need_the_users_approval() {
    let mut server = Server::ready();
    let vault = json!({ "format": 2, "keys": { "test": { "value": "fake_SUPERSECRET_value_123", "hosts": ["127.0.0.1:9"] } } });
    fs::write(server.home.path().join("test-vault.json"), vault.to_string()).unwrap();
    let script = r#"return function()
        return http.get("http://127.0.0.1:9/", { headers = { Authorization = vault("test") } }).status
    end"#;
    server.add_command("call", json!({}), script, json!({ "http": ["127.0.0.1"], "vault": ["test"] }));

    let reply = server.call(1, "call", json!({}));
    assert_eq!(reply["result"]["isError"], true);
    assert!(text(&reply, 0).contains("tb self vault allow test call"), "{reply}");
    assert!(!reply.to_string().contains("SUPERSECRET"));
}

#[test]
fn a_script_reading_stdin_cannot_eat_the_protocol() {
    let mut server = Server::ready();
    server.add_command("slurp", json!({}), "return function() return { got = stdin.read() } end", json!({}));

    let reply = server.call(1, "slurp", json!({}));
    assert_eq!(serde_json::from_str::<Value>(text(&reply, 0)).unwrap(), json!({ "got": "" }));
    assert_eq!(server.request(2, "ping", json!({}))["result"], json!({}));
}

#[test]
fn a_slow_command_does_not_block_other_requests() {
    let mut server = Server::ready();
    server.add_command("slow", json!({}), "return function() time.sleep(3) return 'done' end", json!({}));

    server.send(1, "tools/call", json!({ "name": "slow" }));
    let started = Instant::now();
    assert_eq!(server.request(2, "ping", json!({}))["result"], json!({}));
    assert!(started.elapsed() < Duration::from_secs(2), "ping waited for the slow call");
    let slow = server.wait_for(|m| m["id"] == 1);
    assert_eq!(text(&slow, 0), "\"done\"");
}

#[test]
fn new_commands_show_up_without_a_restart() {
    let mut server = Server::ready();
    assert_eq!(server.request(1, "tools/list", json!({}))["result"]["tools"], json!([]));

    server.add_command("fresh", json!({}), "return function() return 1 end", json!({}));
    server.wait_for(|m| m["method"] == "notifications/tools/list_changed");
    let tools = server.request(2, "tools/list", json!({}));
    assert_eq!(tools["result"]["tools"][0]["name"], "fresh");
}

#[test]
fn closing_stdin_stops_the_server() {
    let mut server = Server::ready();
    server.input = None;
    let deadline = Instant::now() + WAIT;
    let status = loop {
        if let Some(status) = server.child.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "server kept running after stdin closed");
        thread::sleep(Duration::from_millis(50));
    };
    assert!(status.success());
}
