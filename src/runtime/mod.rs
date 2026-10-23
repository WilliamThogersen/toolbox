//! Runs a command's `run.lua` in a sandbox with the toolbox API installed.

mod api;
mod encoding;
mod exec;
mod fs;
mod http;
mod sandbox;
mod time;

use std::rc::Rc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use mlua::serde::SerializeOptions;
use mlua::{Function, Lua, LuaSerdeExt, Value};

use crate::registry::CommandDef;
use crate::vault::VaultStore;
use crate::vault::approval::Caller;

/// JSON `null` becomes Lua `nil`, so `if res.json.field then` behaves as expected.
pub fn ser_options() -> SerializeOptions {
    SerializeOptions::new()
        .serialize_none_to_null(false)
        .serialize_unit_to_null(false)
}

/// Keeps the whole cause chain (`could not read x: permission denied`) in the Lua error.
fn lua_error(err: anyhow::Error) -> mlua::Error {
    mlua::Error::runtime(format!("{err:#}"))
}

/// The longest timeout or sleep a script can ask for. Also keeps `Instant + duration` from overflowing.
const MAX_SECONDS: f64 = 24.0 * 60.0 * 60.0;

/// Seconds from a script (`timeout = 2.5`) as a `Duration`.
fn seconds(secs: f64) -> Result<Duration> {
    if !(0.0..=MAX_SECONDS).contains(&secs) {
        bail!("{secs} is not a valid number of seconds (0 to {MAX_SECONDS})");
    }
    Ok(Duration::from_secs_f64(secs))
}

pub fn run(
    def: &CommandDef,
    args: &serde_json::Value,
    store: Box<dyn VaultStore>,
) -> Result<serde_json::Value> {
    // Read once: the vault approves this exact source, so it must also be what runs.
    let script = def.read_script()?;
    let lua = sandbox::new_lua()?;
    let perms = &def.manifest.permissions;
    api::install(&lua, perms)?;
    encoding::install(&lua)?;
    time::install(&lua)?;
    exec::install(&lua, perms.exec.clone())?;
    fs::install(&lua, Rc::new(fs::FsGuard::new(perms)))?;
    let caller = Caller::new(def, &script);
    http::install(&lua, Rc::new(http::HttpClient::new(perms, caller, store)))?;
    let entry = load_entry(&lua, def, &script)?;
    let result: Value = entry.call(lua.to_value_with(args, ser_options())?)?;
    lua.from_value(result)
        .context("the command returned a value that cannot be turned into JSON")
}

/// Compiles `run.lua` without running it.
pub fn check_syntax(def: &CommandDef) -> Result<()> {
    compile(def, chunk_name(def))
}

/// Like `check_syntax`, but errors call the script `label`, e.g. its path inside a repo.
pub fn check_syntax_as(def: &CommandDef, label: &str) -> Result<()> {
    compile(def, format!("@{label}"))
}

fn compile(def: &CommandDef, chunk: String) -> Result<()> {
    let lua = sandbox::new_lua()?;
    let source = def.read_script()?;
    sandbox::load_source(&lua, &source, chunk).into_function()?;
    Ok(())
}

fn load_entry(lua: &Lua, def: &CommandDef, script: &str) -> Result<Function> {
    let returned: Value = sandbox::load_source(lua, script, chunk_name(def)).eval()?;
    match returned {
        Value::Function(entry) => Ok(entry),
        other => bail!(
            "run.lua must end with `return function(args) ... end`, but it returned {}",
            other.type_name()
        ),
    }
}

fn chunk_name(def: &CommandDef) -> String {
    format!("@{}", def.script_path().display())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Manifest;
    use crate::vault::VaultData;
    use crate::vault::store::MemoryStore;

    fn command(script: &str) -> (tempfile::TempDir, CommandDef) {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("run.lua"), script).unwrap();
        let source = r#"{"name":"t","description":"t"}"#;
        let def = CommandDef {
            manifest: Manifest::parse(source).unwrap(),
            manifest_source: source.to_string(),
            dir: tmp.path().to_path_buf(),
        };
        (tmp, def)
    }

    fn run_script(script: &str, args: serde_json::Value) -> Result<serde_json::Value> {
        let (_tmp, def) = command(script);
        run(&def, &args, Box::new(MemoryStore::new(VaultData::default())))
    }

    #[test]
    fn returns_json_from_lua() {
        let out = run_script(
            r#"return function(args) return { greeting = "hi " .. args.name, n = args.n + 1, list = {1, 2} } end"#,
            serde_json::json!({ "name": "bo", "n": 41 }),
        )
        .unwrap();
        assert_eq!(out, serde_json::json!({ "greeting": "hi bo", "n": 42, "list": [1, 2] }));
    }

    #[test]
    fn script_must_return_a_function() {
        let err = run_script("return 5", serde_json::json!({})).unwrap_err();
        assert!(err.to_string().contains("must end with `return function"));
    }

    #[test]
    fn lua_errors_surface_with_message() {
        let err = run_script(
            r#"return function() error("PR not found") end"#,
            serde_json::json!({}),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("PR not found"));
    }

    #[test]
    fn non_json_results_are_rejected() {
        let err = run_script(
            "return function() return { f = function() end } end",
            serde_json::json!({}),
        )
        .unwrap_err();
        assert!(err.to_string().contains("cannot be turned into JSON"));
    }

    #[test]
    fn check_syntax_catches_errors_without_running() {
        let (_tmp, good) = command("return function() error('never runs') end");
        assert!(check_syntax(&good).is_ok());
        let (_tmp2, bad) = command("return function( end");
        assert!(check_syntax(&bad).is_err());
    }
}
