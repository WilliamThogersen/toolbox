//! Globals for scripts: json, log/print, env, vault, stdin.

use std::io::{self, IsTerminal, Read};

use mlua::{Lua, LuaSerdeExt, Result, Value, Variadic};

use super::ser_options;
use crate::manifest::Permissions;
use crate::vault::inject::placeholder;

pub fn install(lua: &Lua, perms: &Permissions) -> Result<()> {
    install_json(lua)?;
    install_log(lua)?;
    install_env(lua, perms.env.clone())?;
    install_vault(lua, perms.vault.clone())?;
    install_stdin(lua)
}

pub fn denied(kind: &str, what: &str) -> mlua::Error {
    mlua::Error::runtime(format!(
        "{what:?} is not listed in this command's permissions.{kind}"
    ))
}

fn install_json(lua: &Lua) -> Result<()> {
    let json = lua.create_table()?;
    json.set(
        "encode",
        lua.create_function(|lua, value: Value| {
            let value: serde_json::Value = lua.from_value(value)?;
            serde_json::to_string(&value).map_err(mlua::Error::external)
        })?,
    )?;
    json.set(
        "decode",
        lua.create_function(|lua, text: String| {
            let value: serde_json::Value =
                serde_json::from_str(&text).map_err(mlua::Error::external)?;
            lua.to_value_with(&value, ser_options())
        })?,
    )?;
    json.set("null", lua.null())?;
    lua.globals().set("json", json)
}

/// `print` and `log` go to stderr: stdout is reserved for the JSON result.
fn install_log(lua: &Lua) -> Result<()> {
    let log = lua.create_function(|_, values: Variadic<Value>| {
        let parts = values
            .iter()
            .map(|v| v.to_string())
            .collect::<Result<Vec<_>>>()?;
        eprintln!("{}", parts.join("\t"));
        Ok(())
    })?;
    lua.globals().set("print", log.clone())?;
    lua.globals().set("log", log)
}

fn install_env(lua: &Lua, allowed: Vec<String>) -> Result<()> {
    let env = lua.create_table()?;
    env.set(
        "get",
        lua.create_function(move |_, name: String| {
            if !allowed.contains(&name) {
                return Err(denied("env", &name));
            }
            Ok(std::env::var(&name).ok())
        })?,
    )?;
    lua.globals().set("env", env)
}

/// `vault(name)` returns a placeholder, never the value.
fn install_vault(lua: &Lua, declared: Vec<String>) -> Result<()> {
    let vault = lua.create_function(move |_, name: String| {
        if !declared.contains(&name) {
            return Err(denied("vault", &name));
        }
        Ok(placeholder(&name))
    })?;
    lua.globals().set("vault", vault)
}

/// `stdin.read()` returns what was piped in, or `nil` when stdin is a terminal
/// (reading would wait for typing that never comes).
fn install_stdin(lua: &Lua) -> Result<()> {
    let stdin = lua.create_table()?;
    stdin.set(
        "read",
        lua.create_function(|lua, ()| {
            let mut input = io::stdin().lock();
            if input.is_terminal() {
                return Ok(None);
            }
            let mut bytes = Vec::new();
            input
                .read_to_end(&mut bytes)
                .map_err(|e| mlua::Error::runtime(format!("could not read stdin: {e}")))?;
            lua.create_string(bytes).map(Some)
        })?,
    )?;
    lua.globals().set("stdin", stdin)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::sandbox::new_lua;

    fn lua_with(perms: Permissions) -> Lua {
        let lua = new_lua().unwrap();
        install(&lua, &perms).unwrap();
        lua
    }

    fn eval_err(lua: &Lua, code: &str) -> String {
        lua.load(code).exec().unwrap_err().to_string()
    }

    #[test]
    fn json_round_trip_and_null_becomes_nil() {
        let lua = lua_with(Permissions::default());
        let ok: bool = lua
            .load(r#"
                local v = json.decode('{"a":[1,2],"b":null,"c":{}}')
                return v.a[2] == 2 and v.b == nil and json.encode(v.c) == "{}" and json.encode({}) == "{}"
            "#)
            .eval()
            .unwrap();
        assert!(ok);
    }

    #[test]
    fn empty_json_arrays_stay_arrays() {
        let lua = lua_with(Permissions::default());
        let out: String = lua.load(r#"return json.encode(json.decode("[]"))"#).eval().unwrap();
        assert_eq!(out, "[]");
    }

    #[test]
    fn vault_returns_placeholder_only_when_declared() {
        let lua = lua_with(Permissions {
            vault: vec!["github".into()],
            ..Permissions::default()
        });
        let value: String = lua.load(r#"return vault("github")"#).eval().unwrap();
        assert_eq!(value, "{{vault:github}}");
        assert!(eval_err(&lua, r#"vault("stripe")"#).contains("permissions.vault"));
    }

    #[test]
    fn env_requires_permission() {
        let lua = lua_with(Permissions {
            env: vec!["HOME".into()],
            ..Permissions::default()
        });
        let home: Option<String> = lua.load(r#"return env.get("HOME")"#).eval().unwrap();
        assert!(home.is_some());
        assert!(eval_err(&lua, r#"env.get("PATH")"#).contains("permissions.env"));
    }

    #[test]
    fn print_does_not_fail() {
        let lua = lua_with(Permissions::default());
        lua.load(r#"print("a", 1, nil, {}) log("b")"#).exec().unwrap();
    }
}
