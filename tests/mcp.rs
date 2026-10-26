//! End-to-end tests for `tb self mcp`: the real binary as an MCP server over stdio.

use std::ffi::{CStr, CString};
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpListener;
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const WAIT: Duration = Duration::from_secs(15);
const SECRET: &str = "fake_SUPERSECRET_value_123";

struct Server {
    home: TempDir,
    child: Child,
    /// `None` once closed, which is how a client says goodbye.
    input: Option<ChildStdin>,
    messages: Receiver<Value>,
    /// Messages read while waiting for a different one.
    unclaimed: Vec<Value>,
    /// Kept open while the server runs, so its terminal stays alive.
    _terminal: Option<Pty>,
}

enum Session {
    Detached,
    /// The way MCP clients start servers: in a session with a controlling terminal, with
    /// stdin and stdout as pipes.
    Terminal,
}

/// The controller side of a pseudo-terminal, and the path of its terminal side.
struct Pty {
    controller: libc::c_int,
    path: CString,
}

impl Pty {
    fn open() -> Self {
        unsafe {
            let controller = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
            assert!(controller >= 0, "posix_openpt: {}", io::Error::last_os_error());
            assert_eq!(libc::grantpt(controller), 0);
            assert_eq!(libc::unlockpt(controller), 0);
            let path = CStr::from_ptr(libc::ptsname(controller)).to_owned();
            Self { controller, path }
        }
    }
}

impl Drop for Pty {
    fn drop(&mut self) {
        unsafe { libc::close(self.controller) };
    }
}

/// Runs in the child before exec: a new session whose controlling terminal is `path`, also
/// used as stderr (clients let servers inherit theirs). Keeping it open keeps it the
/// controlling terminal: macOS drops that when the last handle closes.
fn take_terminal(path: &CStr) -> io::Result<()> {
    unsafe {
        if libc::setsid() < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = libc::open(path.as_ptr(), libc::O_RDWR);
        if fd < 0 || libc::ioctl(fd, libc::TIOCSCTTY as _, 0) < 0 || libc::dup2(fd, 2) < 0 {
            return Err(io::Error::last_os_error());
        }
        if fd != 2 {
            libc::close(fd);
        }
    }
    Ok(())
}

impl Server {
    fn start() -> Self {
        Self::spawn(Session::Detached)
    }

    fn spawn(session: Session) -> Self {
        let home = tempfile::tempdir().unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_toolbox"));
        cmd.args(["self", "mcp"])
            .env("TOOLBOX_HOME", home.path())
            .env("TOOLBOX_INSECURE_TEST_VAULT", home.path().join("test-vault.json"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let terminal = match session {
            Session::Detached => {
                // No controlling terminal, like an AI agent's shell.
                unsafe {
                    cmd.pre_exec(|| {
                        libc::setsid();
                        Ok(())
                    });
                }
                None
            }
            Session::Terminal => {
                let pty = Pty::open();
                let path = pty.path.clone();
                unsafe { cmd.pre_exec(move || take_terminal(&path)) };
                Some(pty)
            }
        };
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
        Self { home, child, input, messages, unclaimed: Vec::new(), _terminal: terminal }
    }

    /// Starts a server and completes the handshake.
    fn ready() -> Self {
        let mut server = Self::start();
        server.ready_up();
        server
    }

    fn ready_up(&mut self) {
        let init = self.request(0, "initialize", json!({ "protocolVersion": "2025-06-18", "capabilities": {} }));
        assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
        self.notify("notifications/initialized");
    }

    fn vault_file(&self) -> std::path::PathBuf {
        self.home.path().join("test-vault.json")
    }

    /// What `tb self vault allow` stores, written directly: tests have no terminal to say yes on.
    fn allow(&self, secret: &str, command: &str) {
        let dir = self.home.path().join("commands").join(command);
        let manifest = fs::read_to_string(dir.join("command.json")).unwrap();
        let script = fs::read_to_string(dir.join("run.lua")).unwrap();
        let mut vault: Value = serde_json::from_slice(&fs::read(self.vault_file()).unwrap()).unwrap();
        vault["keys"][secret]["commands"][command] = json!(fingerprint(&manifest, &script));
        fs::write(self.vault_file(), vault.to_string()).unwrap();
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

/// Mirrors `vault::approval::fingerprint`, like the copy in tests/cli.rs.
fn fingerprint(manifest: &str, script: &str) -> String {
    let mut hasher = Sha256::new();
    for part in [manifest, script] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    hasher.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Serves one request and echoes its Authorization header back as JSON. Sends the whole
/// request head on the channel.
fn echo_server() -> (String, Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}/", listener.local_addr().unwrap().port());
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let head: Vec<String> = BufReader::new(&stream)
            .lines()
            .map_while(Result::ok)
            .take_while(|line| !line.is_empty())
            .collect();
        let auth = head
            .iter()
            .find_map(|l| l.strip_prefix("authorization: ").or_else(|| l.strip_prefix("Authorization: ")))
            .unwrap_or("");
        let body = json!({ "you_sent": auth }).to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
        tx.send(head.join("\n")).unwrap();
    });
    (url, rx)
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
fn vault_keys_need_approval_and_stay_redacted() {
    let mut server = Server::ready();
    let (url, received) = echo_server();
    let host = url.trim_start_matches("http://").trim_end_matches('/');
    let vault = json!({ "format": 2, "keys": { "test": { "value": SECRET, "hosts": [host] } } });
    fs::write(server.vault_file(), vault.to_string()).unwrap();
    let script = r#"return function(args)
        return http.get(args.url, { headers = { Authorization = "Bearer " .. vault("test") } }).json
    end"#;
    let args = json!({ "url": { "type": "string", "required": true } });
    server.add_command("call", args, script, json!({ "http": ["127.0.0.1"], "vault": ["test"] }));

    let refused = server.call(1, "call", json!({ "url": url }));
    assert_eq!(refused["result"]["isError"], true);
    assert!(text(&refused, 0).contains("tb self vault setup call"), "{refused}");

    server.allow("test", "call");
    let reply = server.call(2, "call", json!({ "url": url }));
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    assert!(received.recv_timeout(WAIT).unwrap().contains(SECRET), "the server never got the key");
    let echoed: Value = serde_json::from_str(text(&reply, 0)).unwrap();
    assert_eq!(echoed["you_sent"], "Bearer [REDACTED:test]");
    assert!(!reply.to_string().contains("SUPERSECRET"));
}

#[test]
fn tool_calls_never_get_the_clients_terminal() {
    // Otherwise a command allowed to exec `tb` could open a vault prompt on the user's terminal.
    let mut server = Server::spawn(Session::Terminal);
    server.ready_up();
    let script = r#"return function()
        local out = exec("sh", { "-c", "( exec 3</dev/tty ) 2>/dev/null && echo terminal || echo none" })
        return (out.stdout:gsub("%s+$", ""))
    end"#;
    server.add_command("tty", json!({}), script, json!({ "exec": ["sh"] }));

    let reply = server.call(1, "tty", json!({}));
    assert_eq!(text(&reply, 0), "\"none\"", "{reply}");
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

/// A command that sleeps, then leaves a file behind: proof it was not stopped in time.
fn add_sleeper(server: &Server, name: &str) -> std::path::PathBuf {
    let out = server.home.path().join(format!("{name}-ran"));
    let script = format!(r#"return function() time.sleep(2) fs.write("{}", "ran") return "done" end"#, out.display());
    server.add_command(name, json!({}), &script, json!({ "write": [server.home.path()] }));
    out
}

#[test]
fn a_cancelled_call_is_stopped_and_gets_no_reply() {
    let mut server = Server::ready();
    let ran = add_sleeper(&server, "nap");

    server.send(1, "tools/call", json!({ "name": "nap" }));
    thread::sleep(Duration::from_millis(500));
    server.write(json!({ "jsonrpc": "2.0", "method": "notifications/cancelled", "params": { "requestId": 1 } }));
    thread::sleep(Duration::from_secs(3));

    assert!(!ran.exists(), "the cancelled call kept running");
    assert_eq!(server.request(2, "ping", json!({}))["result"], json!({}));
    assert!(server.unclaimed.iter().all(|m| m["id"] != 1), "a cancelled call was answered");
}

#[test]
fn closing_stdin_stops_the_server_and_its_calls() {
    let mut server = Server::ready();
    let ran = add_sleeper(&server, "nap");
    server.send(1, "tools/call", json!({ "name": "nap" }));
    thread::sleep(Duration::from_millis(500));

    server.input = None;
    let deadline = Instant::now() + Duration::from_secs(1);
    let status = loop {
        if let Some(status) = server.child.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "server waited for a running call after stdin closed");
        thread::sleep(Duration::from_millis(50));
    };
    assert!(status.success());
    thread::sleep(Duration::from_secs(3));
    assert!(!ran.exists(), "a call kept running after the server stopped");
}
