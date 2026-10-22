//! Runs a command's `run.lua` in a sandbox with the toolbox API installed.

mod api;
mod http;
mod sandbox;

use std::fs;
use std::rc::Rc;

use anyhow::{Context, Result, bail};
use mlua::serde::SerializeOptions;
use mlua::{Function, Lua, LuaSerdeExt, Value};

use crate::registry::CommandDef;
use crate::vault::VaultStore;

/// JSON `null` becomes Lua `nil`, so `if res.json.field then` behaves as expected.
pub fn ser_options() -> SerializeOptions {
    SerializeOptions::new()
        .serialize_none_to_null(false)
        .serialize_unit_to_null(false)
}

pub fn run(
    def: &CommandDef,
    args: &serde_json::Value,
    store: Box<dyn VaultStore>,
) -> Result<serde_json::Value> {
    let lua = sandbox::new_lua()?;
    api::install(&lua, &def.manifest.permissions)?;
    http::install(
        &lua,
        Rc::new(http::HttpClient::new(&def.manifest.permissions, store)),
    )?;
    let entry = load_entry(&lua, def)?;
    let result: Value = entry.call(lua.to_value_with(args, ser_options())?)?;
    lua.from_value(result)
        .context("the command returned a value that cannot be turned into JSON")
}

/// Compiles `run.lua` without running it.
pub fn check_syntax(def: &CommandDef) -> Result<()> {
    let lua = sandbox::new_lua()?;
    let source = read_script(def)?;
    lua.load(&source).set_name(chunk_name(def)).into_function()?;
    Ok(())
}

fn load_entry(lua: &Lua, def: &CommandDef) -> Result<Function> {
    let source = read_script(def)?;
    let returned: Value = lua.load(&source).set_name(chunk_name(def)).eval()?;
    match returned {
        Value::Function(entry) => Ok(entry),
        other => bail!(
            "run.lua must end with `return function(args) ... end`, but it returned {}",
            other.type_name()
        ),
    }
}

fn read_script(def: &CommandDef) -> Result<String> {
    let path = def.script_path();
    fs::read_to_string(&path).with_context(|| format!("could not read {}", path.display()))
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
        fs::write(tmp.path().join("run.lua"), script).unwrap();
        let manifest = Manifest::parse(r#"{"name":"t","description":"t"}"#).unwrap();
        let def = CommandDef {
            manifest,
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
