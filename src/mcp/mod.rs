//! `tb self mcp`: serves the user's commands as MCP tools over stdio
//! (newline-delimited JSON-RPC 2.0). Built-ins under `tb self` are not exposed, so an MCP
//! client gets no more than an agent's shell: it can run commands, never manage the vault.

mod tools;

use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::Result;
use serde_json::{Value, json};

/// Newest first. A client asking for one of these gets it, anything else gets the newest.
const PROTOCOL_VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

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
    Notification { method: String },
    /// A response to a request we sent. We send none, so there is nothing to do.
    Response,
    Invalid { id: Value, error: RpcError },
}

/// Reads messages until the client closes stdin. Tool calls run on their own threads, so a slow
/// command doesn't hold up pings or other calls; replies may come back in any order.
pub fn serve(commands_dir: &Path) -> Result<ExitCode> {
    let mut calls: Vec<JoinHandle<()>> = Vec::new();
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
                let dir = commands_dir.to_path_buf();
                calls.push(thread::spawn(move || {
                    // Stdout is gone only when the client is: nobody is left to tell.
                    let _ = send(&reply(id, tools::call(&dir, &params)));
                }));
            }
            Incoming::Request { id, method, params } => send(&reply(id, handle(commands_dir, &method, &params)))?,
            Incoming::Notification { method } if method == "notifications/initialized" && !watching => {
                watching = true;
                watch(commands_dir.to_path_buf());
            }
            Incoming::Notification { .. } | Incoming::Response => {}
            Incoming::Invalid { id, error } => send(&reply(id, Err(error)))?,
        }
    }
    for call in calls {
        let _ = call.join();
    }
    Ok(ExitCode::SUCCESS)
}

fn handle(commands_dir: &Path, method: &str, params: &Value) -> Result<Value, RpcError> {
    match method {
        "initialize" => Ok(initialize(params)),
        "ping" => Ok(json!({})),
        "tools/list" => tools::list(commands_dir),
        "tools/call" => tools::call(commands_dir, params),
        _ => Err(RpcError::new(METHOD_NOT_FOUND, format!("unknown method {method:?}"))),
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
    let invalid = |id: Value, code, message: &str| Incoming::Invalid { id, error: RpcError::new(code, message) };
    let Ok(message) = serde_json::from_str::<Value>(line) else {
        return invalid(Value::Null, PARSE_ERROR, "message is not valid JSON");
    };
    let Some(fields) = message.as_object() else {
        return invalid(Value::Null, INVALID_REQUEST, "expected one JSON-RPC message object (batches are not supported)");
    };
    let method = fields.get("method").and_then(Value::as_str).map(str::to_string);
    match (method, fields.get("id").cloned()) {
        (Some(method), Some(id)) => Incoming::Request {
            id,
            method,
            params: fields.get("params").cloned().unwrap_or_else(|| json!({})),
        },
        (Some(method), None) => Incoming::Notification { method },
        (None, Some(_)) if fields.contains_key("result") || fields.contains_key("error") => Incoming::Response,
        (None, id) => invalid(id.unwrap_or(Value::Null), INVALID_REQUEST, "message has no method"),
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
        match parse(line) {
            Incoming::Request { id, method, params } => reply(id, handle(Path::new("/definitely/not/here"), &method, &params)),
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

        let unknown = request(r#"{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}"#);
        assert_eq!(unknown["result"]["protocolVersion"], PROTOCOL_VERSIONS[0]);
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
        assert_eq!(request(r#"{"jsonrpc":"2.0","id":4,"method":"resources/list"}"#)["error"]["code"], METHOD_NOT_FOUND);
        let unknown_tool = request(r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"nope"}}"#);
        assert_eq!(unknown_tool["error"]["code"], INVALID_PARAMS);
        assert_eq!(request("{not json")["error"]["code"], PARSE_ERROR);
        assert_eq!(request("[]")["error"]["code"], INVALID_REQUEST);
        let no_method = request(r#"{"jsonrpc":"2.0","id":6}"#);
        assert_eq!((no_method["id"].clone(), no_method["error"]["code"].clone()), (json!(6), json!(INVALID_REQUEST)));
    }

    #[test]
    fn notifications_and_responses_get_no_reply() {
        assert!(matches!(parse(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#), Incoming::Notification { .. }));
        assert!(matches!(parse(r#"{"jsonrpc":"2.0","id":7,"result":{}}"#), Incoming::Response));
    }
}
