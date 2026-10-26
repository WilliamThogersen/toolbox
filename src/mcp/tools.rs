use std::path::Path;
use std::process::{Command, Output, Stdio};

use serde_json::{Map, Value, json};

use super::running::Running;
use super::{INTERNAL_ERROR, INVALID_PARAMS, RpcError};
use crate::command::manifest::{ArgSpec, ArgType, Manifest};
use crate::command::registry::{self, Registry};
use crate::sys;

pub fn list(commands_dir: &Path) -> Result<Value, RpcError> {
    let registry = load(commands_dir)?;
    let tools: Vec<Value> = registry.commands.iter().map(|def| tool(&def.manifest)).collect();
    Ok(json!({ "tools": tools }))
}

pub fn call(commands_dir: &Path, params: &Value, running: &Running, id: &str) -> Result<Value, RpcError> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new(INVALID_PARAMS, "tools/call needs a tool name"))?;
    let registry = load(commands_dir)?;
    let def = registry
        .find(name)
        .ok_or_else(|| RpcError::new(INVALID_PARAMS, format!("unknown tool {name:?}")))?;
    let empty = Map::new();
    let arguments = match params.get("arguments") {
        None | Some(Value::Null) => &empty,
        Some(Value::Object(arguments)) => arguments,
        Some(_) => return Ok(failure("arguments must be an object")),
    };
    Ok(match cli_args(&def.manifest, arguments) {
        Ok(args) => run(name, &args, running, id),
        Err(problem) => failure(&problem),
    })
}

pub fn fingerprint(commands_dir: &Path) -> Option<Vec<String>> {
    let registry = registry::load(commands_dir).ok()?;
    Some(registry.commands.into_iter().map(|def| def.manifest_source).collect())
}

fn load(commands_dir: &Path) -> Result<Registry, RpcError> {
    registry::load(commands_dir).map_err(|err| RpcError::new(INTERNAL_ERROR, format!("{err:#}")))
}

fn tool(manifest: &Manifest) -> Value {
    json!({
        "name": manifest.name,
        "description": manifest.description,
        "inputSchema": input_schema(manifest),
    })
}

fn input_schema(manifest: &Manifest) -> Value {
    let properties: Map<String, Value> = manifest
        .args
        .iter()
        .map(|(name, spec)| (name.clone(), property(spec)))
        .collect();
    let required: Vec<&String> = manifest
        .args
        .iter()
        .filter(|(_, spec)| spec.required)
        .map(|(name, _)| name)
        .collect();
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false,
    })
}

fn property(spec: &ArgSpec) -> Value {
    let fields = [
        Some(("type", json!(type_name(spec.kind)))),
        (!spec.description.is_empty()).then(|| ("description", json!(spec.description))),
        spec.default.clone().map(|default| ("default", default)),
    ];
    Value::Object(fields.into_iter().flatten().map(|(k, v)| (k.to_string(), v)).collect())
}

fn type_name(kind: ArgType) -> &'static str {
    match kind {
        ArgType::String => "string",
        ArgType::Integer => "integer",
        ArgType::Number => "number",
        ArgType::Boolean => "boolean",
    }
}

fn a_type(kind: ArgType) -> &'static str {
    match kind {
        ArgType::Integer => "an integer",
        ArgType::String => "a string",
        ArgType::Number => "a number",
        ArgType::Boolean => "a boolean",
    }
}

fn cli_args(manifest: &Manifest, arguments: &Map<String, Value>) -> Result<Vec<String>, String> {
    if let Some(unknown) = arguments.keys().find(|name| !manifest.args.contains_key(*name)) {
        let known: Vec<&String> = manifest.args.keys().collect();
        return Err(format!("unknown argument {unknown:?}. {} takes: {known:?}", manifest.name));
    }
    manifest
        .args
        .iter()
        .map(|(name, spec)| match arguments.get(name) {
            None | Some(Value::Null) if spec.required => Err(format!("missing required argument {name:?}")),
            None | Some(Value::Null) => Ok(None),
            Some(value) => flag(name, spec, value),
        })
        .filter_map(Result::transpose)
        .collect()
}

fn flag(name: &str, spec: &ArgSpec, value: &Value) -> Result<Option<String>, String> {
    let wrong_type = || format!("argument {name:?} must be {}, got {value}", a_type(spec.kind));
    match (spec.kind, value) {
        (ArgType::Boolean, Value::Bool(true)) => Ok(Some(format!("--{name}"))),
        (ArgType::Boolean, Value::Bool(false)) if spec.default == Some(Value::Bool(true)) => Err(format!(
            "argument {name:?} is a flag that is on by default and can't be turned off"
        )),
        (ArgType::Boolean, Value::Bool(false)) => Ok(None),
        (ArgType::String, Value::String(text)) if text.contains('\0') => {
            Err(format!("argument {name:?} must not contain a NUL character"))
        }
        (ArgType::String, Value::String(text)) => Ok(Some(format!("--{name}={text}"))),
        (ArgType::Integer, Value::Number(n)) if n.is_i64() => Ok(Some(format!("--{name}={n}"))),
        (ArgType::Number, Value::Number(n)) => Ok(Some(format!("--{name}={n}"))),
        _ => Err(wrong_type()),
    }
}

fn run(name: &str, args: &[String], running: &Running, id: &str) -> Value {
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(err) => return failure(&format!("could not find the toolbox binary: {err}")),
    };
    let mut command = Command::new(exe);
    command
        .arg(name)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    sys::start_new_session(&mut command);
    let child = match command.spawn() {
        Ok(child) => child,
        Err(err) => return failure(&format!("could not start {name}: {err}")),
    };
    running.started(id, child.id());
    match child.wait_with_output() {
        Ok(output) => outcome(&output),
        Err(err) => failure(&format!("could not run {name}: {err}")),
    }
}

fn outcome(output: &Output) -> Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let lines: Vec<&str> = stderr.lines().filter(|line| !line.trim().is_empty()).collect();
    if output.status.success() {
        return result(false, stdout.trim_end(), &lines);
    }
    let reported = lines
        .split_last()
        .and_then(|(last, logs)| Some((error_message(last)?, logs)));
    match reported {
        Some((message, logs)) => result(true, &message, logs),
        None => result(true, &format!("the command failed ({})", output.status), &lines),
    }
}

fn error_message(line: &str) -> Option<String> {
    let parsed: Value = serde_json::from_str(line).ok()?;
    parsed.get("error")?.as_str().map(str::to_string)
}

fn result(is_error: bool, text: &str, logs: &[&str]) -> Value {
    let log_block = (!logs.is_empty()).then(|| format!("Log output:\n{}", logs.join("\n")));
    let content: Vec<Value> = [Some(text.to_string()), log_block]
        .into_iter()
        .flatten()
        .map(|text| json!({ "type": "text", "text": text }))
        .collect();
    json!({ "content": content, "isError": is_error })
}

fn failure(message: &str) -> Value {
    result(true, message, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> Manifest {
        Manifest::parse(
            r#"{
                "name": "pr",
                "description": "Show a PR",
                "args": {
                    "repo": { "type": "string", "required": true, "description": "owner/repo" },
                    "limit": { "type": "integer", "default": 5 },
                    "ratio": { "type": "number" },
                    "verbose": { "type": "boolean" },
                    "color": { "type": "boolean", "default": true }
                }
            }"#,
        )
        .unwrap()
    }

    #[expect(clippy::needless_pass_by_value, reason = "tests pass `json!(...)` values as they are")]
    fn args(value: Value) -> Result<Vec<String>, String> {
        cli_args(&manifest(), value.as_object().unwrap())
    }

    #[test]
    fn schema_lists_types_required_descriptions_and_defaults() {
        let schema = input_schema(&manifest());
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["required"], json!(["repo"]));
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["properties"]["repo"], json!({ "type": "string", "description": "owner/repo" }));
        assert_eq!(schema["properties"]["limit"], json!({ "type": "integer", "default": 5 }));
        assert_eq!(schema["properties"]["ratio"], json!({ "type": "number" }));
        assert_eq!(schema["properties"]["verbose"], json!({ "type": "boolean" }));
    }

    #[test]
    fn a_command_without_args_takes_an_empty_object() {
        let bare = Manifest::parse(r#"{"name":"t","description":"t"}"#).unwrap();
        let schema = input_schema(&bare);
        assert_eq!(schema["properties"], json!({}));
        assert_eq!(schema["required"], json!([]));
    }

    #[test]
    fn arguments_become_equals_flags() {
        let flags = args(json!({ "repo": "-rf /", "limit": 3, "ratio": 0.5, "verbose": true })).unwrap();
        assert_eq!(flags, ["--limit=3", "--ratio=0.5", "--repo=-rf /", "--verbose"]);
    }

    #[test]
    fn false_and_null_leave_a_flag_out() {
        let flags = args(json!({ "repo": "a/b", "verbose": false, "limit": null })).unwrap();
        assert_eq!(flags, ["--repo=a/b"]);
    }

    #[test]
    fn bad_arguments_explain_themselves() {
        let err = |value| args(value).unwrap_err();
        assert!(err(json!({})).contains("missing required argument \"repo\""));
        assert!(err(json!({ "repo": null })).contains("missing required argument"));
        assert!(err(json!({ "repo": "a/b", "nope": 1 })).contains("unknown argument \"nope\""));
        assert!(err(json!({ "repo": 5 })).contains("must be a string"));
        assert!(err(json!({ "repo": "a/b", "limit": 2.5 })).contains("must be an integer"));
        assert!(err(json!({ "repo": "a/b", "ratio": "1" })).contains("must be a number"));
        assert!(err(json!({ "repo": "a/b", "verbose": "yes" })).contains("must be a boolean"));
        assert!(err(json!({ "repo": "a\0b" })).contains("NUL"));
        assert!(err(json!({ "repo": "a/b", "color": false })).contains("can't be turned off"));
    }

    #[test]
    fn failed_runs_surface_the_error_and_the_logs() {
        let line = r#"{"error":"command \"pr\" failed: PR not found"}"#;
        assert_eq!(error_message(line).unwrap(), "command \"pr\" failed: PR not found");
        assert_eq!(error_message("plain log line"), None);

        let out = result(true, "boom", &["step 1", "step 2"]);
        assert_eq!(out["isError"], true);
        assert_eq!(out["content"][0]["text"], "boom");
        assert_eq!(out["content"][1]["text"], "Log output:\nstep 1\nstep 2");
        assert_eq!(result(false, "{}", &[])["content"].as_array().unwrap().len(), 1);
    }
}
