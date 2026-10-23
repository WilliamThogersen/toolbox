//! `tb self mcp`: serves the user's commands as MCP tools over stdio
//! (newline-delimited JSON-RPC 2.0). Built-ins under `tb self` are not exposed, and calls run
//! without a terminal, so an MCP client gets no more than an agent's shell: it can run
//! commands, never manage the vault.

mod running;
mod tools;

use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::Result;
use serde_json::{Value, json};

use running::Running;

/// Newest first. A client asking for one of these gets it, anything else gets the newest.
/// 2025-03-26 is left out: it requires JSON-RPC batches, which this server doesn't take.
const PROTOCOL_VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2024-11-05"];

/// How often the commands folder is checked, to tell the client when its tools changed.
const WATCH_INTERVAL: Duration = Duration::from_secs(2);

const INSTRUCTIONS: &str = "Each tool is one of the user's toolbox commands: a small sandboxed Lua script that \
returns JSON. A tool that needs an API key fails until the user allows it, and its error says what to ask the user \
to run. To add or change a tool, use the shell: `tb self guide` is the reference and `tb self new <name>` starts one. \
New and changed tools show up here within a few seconds.";

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;
const INTERNAL_ERROR: i64 = -32603;

#[derive(Debug)]
pub struct RpcError {
    code: i64,
    message: String,
}

impl RpcError {
    fn new(code: i64, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }
}

enum Incoming {
    Request { id: Value, method: String, params: Value },
    Notification { method: String, params: Value },
    /// A response to a request we sent. We send none, so there is nothing to do.
    Response,
    Invalid { id: Value, error: RpcError },
}

#[derive(Clone)]
struct Server {
    commands_dir: PathBuf,
    running: Running,
}

/// Reads messages until the client closes stdin, then stops every call still running: nobody
/// is left to read the results.
pub fn serve(commands_dir: &Path) -> Result<ExitCode> {
    let server = Server { commands_dir: commands_dir.to_path_buf(), running: Running::default() };
    let mut calls = Vec::new();
    let read = server.read_messages(&mut calls);
    server.running.stop_all();
    for call in calls {
        let _ = call.join();
    }
    read.map(|()| ExitCode::SUCCESS)
}

impl Server {
    /// Tool calls run on their own threads, so a slow command doesn't hold up pings or other
    /// calls; replies may come back in any order.
    fn read_messages(&self, calls: &mut Vec<JoinHandle<()>>) -> Result<()> {
        let mut watching = false;
        for line in io::stdin().lock().lines() {
            let line = match line {
                Ok(line) => line,
                Err(err) if err.kind() == io::ErrorKind::InvalidData => {
                    send(&reply(Value::Null, Err(RpcError::new(PARSE_ERROR, "message is not UTF-8"))))?;
                    continue;
                }
                Err(err) => return Err(err.into()),
            };
            if line.trim().is_empty() {
                continue;
            }
            match parse(&line) {
                Incoming::Request { id, method, params } if method == "tools/call" => {
                    calls.retain(|call| !call.is_finished());
                    calls.push(self.call_in_background(id, params));
                }
                Incoming::Request { id, method, params } => {
                    let outcome = self.handle(&id, &method, &params);
                    send(&reply(id, outcome))?;
                }
                Incoming::Notification { method, params } => match method.as_str() {
                    "notifications/initialized" if !watching => {
                        watching = true;
                        watch(self.commands_dir.clone());
                    }
                    "notifications/cancelled" => {
                        if let Some(id) = params.get("requestId") {
                            self.running.cancel(&id.to_string());
                        }
                    }
                    _ => {}
                },
                Incoming::Response => {}
                Incoming::Invalid { id, error } => send(&reply(id, Err(error)))?,
            }
        }
        Ok(())
    }

    fn handle(&self, id: &Value, method: &str, params: &Value) -> Result<Value, RpcError> {
        match method {
            "initialize" => Ok(initialize(params)),
            "ping" => Ok(json!({})),
            "tools/list" => tools::list(&self.commands_dir),
            "tools/call" => tools::call(&self.commands_dir, params, &self.running, &id.to_string()),
            _ => Err(RpcError::new(METHOD_NOT_FOUND, format!("unknown method {method:?}"))),
        }
    }

    /// Replies when the call is done, unless the client cancelled it meanwhile.
    fn call_in_background(&self, id: Value, params: Value) -> JoinHandle<()> {
        let key = id.to_string();
        self.running.begin(&key);
        let server = self.clone();
        thread::spawn(move || {
            let outcome = server.handle(&id, "tools/call", &params);
            if server.running.finish(&key) {
                // Stdout is gone only when the client is: nobody is left to tell.
                let _ = send(&reply(id, outcome));
            }
        })
    }
}

fn initialize(params: &Value) -> Value {
    let asked = params.get("protocolVersion").and_then(Value::as_str);
    let version = asked
        .filter(|version| PROTOCOL_VERSIONS.contains(version))
        .unwrap_or(PROTOCOL_VERSIONS[0]);
    json!({
        "protocolVersion": version,
        "capabilities": { "tools": { "listChanged": true } },
        "serverInfo": { "name": "toolbox", "version": env!("CARGO_PKG_VERSION") },
        "instructions": INSTRUCTIONS,
    })
}

fn parse(line: &str) -> Incoming {
    let invalid = |id: Value, message: &str| Incoming::Invalid { id, error: RpcError::new(INVALID_REQUEST, message) };
    let Ok(message) = serde_json::from_str::<Value>(line) else {
        return Incoming::Invalid { id: Value::Null, error: RpcError::new(PARSE_ERROR, "message is not valid JSON") };
    };
    let Some(fields) = message.as_object() else {
        return invalid(Value::Null, "expected one JSON-RPC message object (batches are not supported)");
    };
    let method = fields.get("method").and_then(Value::as_str).map(str::to_string);
    if method.is_none() && (fields.contains_key("result") || fields.contains_key("error")) {
        return Incoming::Response;
    }
    let id = fields.get("id").cloned();
    // JSON-RPC ids are strings or numbers, and MCP forbids null.
    let usable_id = id.clone().filter(|id| id.is_string() || id.is_number());
    let reply_to = usable_id.clone().unwrap_or(Value::Null);
    if fields.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return invalid(reply_to, "jsonrpc must be \"2.0\"");
    }
    let params = fields.get("params").cloned().unwrap_or_else(|| json!({}));
    match (method, id, usable_id) {
        (None, _, _) => invalid(reply_to, "message has no method"),
        (Some(method), None, _) => Incoming::Notification { method, params },
        (Some(_), Some(_), None) => invalid(Value::Null, "id must be a string or a number"),
        (Some(method), Some(_), Some(id)) => Incoming::Request { id, method, params },
    }
}

fn reply(id: Value, outcome: Result<Value, RpcError>) -> Value {
    match outcome {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err(err) => json!({ "jsonrpc": "2.0", "id": id, "error": { "code": err.code, "message": err.message } }),
    }
}

/// One message per line. Holding the stdout lock for the whole line keeps replies from
/// different threads from interleaving.
fn send(message: &Value) -> Result<()> {
    let line = serde_json::to_string(message)? + "\n";
    let mut stdout = io::stdout().lock();
    stdout.write_all(line.as_bytes())?;
    stdout.flush()?;
    Ok(())
}

/// Tells the client to fetch the tool list again after a command is added, removed or its
/// `command.json` changes, so a command an agent just wrote is usable right away.
fn watch(commands_dir: PathBuf) {
    thread::spawn(move || {
        let mut seen = tools::fingerprint(&commands_dir);
        loop {
            thread::sleep(WATCH_INTERVAL);
            let now = tools::fingerprint(&commands_dir);
            if now == seen {
                continue;
            }
            seen = now;
            if send(&json!({ "jsonrpc": "2.0", "method": "notifications/tools/list_changed" })).is_err() {
                return;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(line: &str) -> Value {
        let server = Server { commands_dir: PathBuf::from("/definitely/not/here"), running: Running::default() };
        match parse(line) {
            Incoming::Request { id, method, params } => {
                let outcome = server.handle(&id, &method, &params);
                reply(id, outcome)
            }
            Incoming::Invalid { id, error } => reply(id, Err(error)),
            _ => panic!("not a request: {line}"),
        }
    }

    #[test]
    fn initialize_agrees_on_a_known_version_or_offers_the_newest() {
        let known = request(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#);
        assert_eq!(known["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(known["result"]["serverInfo"]["name"], "toolbox");
        assert_eq!(known["result"]["capabilities"]["tools"]["listChanged"], true);

        for unsupported in ["1999-01-01", "2025-03-26"] {
            let line = json!({ "jsonrpc": "2.0", "id": 2, "method": "initialize", "params": { "protocolVersion": unsupported } });
            assert_eq!(request(&line.to_string())["result"]["protocolVersion"], PROTOCOL_VERSIONS[0]);
        }
    }

    #[test]
    fn ping_and_an_empty_tool_list() {
        assert_eq!(request(r#"{"jsonrpc":"2.0","id":"a","method":"ping"}"#)["result"], json!({}));
        let list = request(r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#);
        assert_eq!(list["id"], 3);
        assert_eq!(list["result"]["tools"], json!([]));
    }

    #[test]
    fn protocol_errors_use_json_rpc_codes() {
        let code = |line: &str| request(line)["error"]["code"].clone();
        assert_eq!(code(r#"{"jsonrpc":"2.0","id":4,"method":"resources/list"}"#), METHOD_NOT_FOUND);
        assert_eq!(code(r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"nope"}}"#), INVALID_PARAMS);
        assert_eq!(code("{not json"), PARSE_ERROR);
        assert_eq!(code("[]"), INVALID_REQUEST);
        let no_method = request(r#"{"jsonrpc":"2.0","id":6}"#);
        assert_eq!((no_method["id"].clone(), no_method["error"]["code"].clone()), (json!(6), json!(INVALID_REQUEST)));
    }

    #[test]
    fn requests_need_json_rpc_2_and_a_string_or_number_id() {
        let missing = request(r#"{"id":1,"method":"ping"}"#);
        assert_eq!((missing["id"].clone(), missing["error"]["code"].clone()), (json!(1), json!(INVALID_REQUEST)));
        assert_eq!(request(r#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#)["error"]["code"], INVALID_REQUEST);
        for id in ["null", r#"{"x":1}"#, "[1]", "true"] {
            let reply = request(&format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"ping"}}"#));
            assert_eq!((reply["id"].clone(), reply["error"]["code"].clone()), (Value::Null, json!(INVALID_REQUEST)), "id {id}");
        }
    }

    #[test]
    fn notifications_and_responses_get_no_reply() {
        let cancel = parse(r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":3}}"#);
        assert!(matches!(cancel, Incoming::Notification { params, .. } if params["requestId"] == 3));
        assert!(matches!(parse(r#"{"jsonrpc":"2.0","id":7,"result":{}}"#), Incoming::Response));
        assert!(matches!(parse(r#"{"jsonrpc":"2.0","result":{}}"#), Incoming::Response));
        assert!(matches!(parse(r#"{"error":{"code":1,"message":"x"}}"#), Incoming::Response));
    }
}
