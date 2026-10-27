use std::io::{self, IsTerminal};

use mlua::{Lua, LuaSerdeExt, LuaString, Result, Value, Variadic};

use super::{lua_error, read_capped, ser_options};
use crate::cli::screen::printable;
use crate::command::manifest::Permissions;
use crate::vault::inject::{Encoding, placeholder};
use crate::vault::names::{self, NAME_RULES};

pub fn install(lua: &Lua, perms: &Permissions) -> Result<()> {
    install_json(lua)?;
    install_yaml(lua)?;
    install_log(lua)?;
    install_env(lua, perms.env.clone())?;
    install_vault(lua, perms.vault.clone())?;
    install_stdin(lua)
}

const MAX_YAML_BYTES: usize = 4 << 20;

pub fn needs_flag(flag: &str, what: &str) -> mlua::Error {
    mlua::Error::runtime(format!("{what} needs \"{flag}\": true in this command's permissions"))
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

fn install_yaml(lua: &Lua) -> Result<()> {
    let yaml = lua.create_table()?;
    yaml.set(
        "encode",
        lua.create_function(|lua, value: Value| {
            let value: serde_json::Value = lua.from_value(value)?;
            serde_norway::to_string(&value).map_err(mlua::Error::external)
        })?,
    )?;
    yaml.set(
        "decode",
        lua.create_function(|lua, text: LuaString| {
            if text.as_bytes().len() > MAX_YAML_BYTES {
                return Err(mlua::Error::runtime(format!("yaml.decode takes at most {} MB", MAX_YAML_BYTES >> 20)));
            }
            let value: serde_norway::Value = serde_norway::from_slice(&text.as_bytes()).map_err(mlua::Error::external)?;
            lua.to_value_with(&value, ser_options())
        })?,
    )?;
    lua.globals().set("yaml", yaml)
}

fn install_log(lua: &Lua) -> Result<()> {
    let log = lua.create_function(|_, values: Variadic<Value>| {
        let parts = values
            .iter()
            .map(mlua::Value::to_string)
            .collect::<Result<Vec<_>>>()?;
        let line = parts.join("\t");
        if io::stderr().is_terminal() {
            eprintln!("{}", printable(&line));
        } else {
            eprintln!("{line}");
        }
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

fn install_vault(lua: &Lua, declared: Vec<String>) -> Result<()> {
    let vault = lua.create_function(move |_, (name, encoding): (String, Option<String>)| {
        if !names::is_secret_name(&name) {
            return Err(mlua::Error::runtime(format!(
                "{name:?} is not a valid vault key name ({NAME_RULES})"
            )));
        }
        if !names::declared(&declared, &name) {
            return Err(denied("vault", &name));
        }
        let encoding = match encoding.as_deref() {
            None => Encoding::Raw,
            Some(label) => Encoding::parse(label).map_err(lua_error)?,
        };
        Ok(placeholder(&name, encoding))
    })?;
    lua.globals().set("vault", vault)
}

fn install_stdin(lua: &Lua) -> Result<()> {
    let stdin = lua.create_table()?;
    stdin.set(
        "read",
        lua.create_function(|lua, ()| {
            let input = io::stdin().lock();
            if input.is_terminal() {
                return Ok(None);
            }
            let bytes = read_capped(input, "stdin").map_err(lua_error)?;
            lua.create_string(bytes).map(Some)
        })?,
    )?;
    lua.globals().set("stdin", stdin)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::sandbox::new_lua;

    #[expect(clippy::needless_pass_by_value, reason = "tests build the permissions in the call")]
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
    fn yaml_round_trip() {
        let lua = lua_with(Permissions::default());
        let ok: bool = lua
            .load(r#"
                local v = yaml.decode("name: shop\nphp_version: '8.3'\nports: [80, 443]\nhooks:\n  post-start: ~\nweb:\n  env: { A: 1 }\n")
                local back = yaml.decode(yaml.encode(v))
                return v.name == "shop" and v.php_version == "8.3" and v.ports[2] == 443
                   and v.hooks["post-start"] == nil and v.web.env.A == 1 and back.web.env.A == 1
            "#)
            .eval()
            .unwrap();
        assert!(ok);
        let text: String = lua.load(r#"return yaml.encode({ name = "shop", list = { "a", "b" } })"#).eval().unwrap();
        assert_eq!(text, "list:\n- a\n- b\nname: shop\n");
    }

    #[test]
    fn yaml_bombs_and_bad_yaml_are_errors() {
        let lua = lua_with(Permissions::default());
        let bomb = (1..=9).fold("a0: &a0 [x, x, x, x, x, x, x, x, x]".to_string(), |text, n| {
            format!("{text}\na{n}: &a{n} [*a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}]", p = n - 1)
        });
        lua.globals().set("bomb", bomb).unwrap();
        assert!(eval_err(&lua, "yaml.decode(bomb)").contains("repetition limit"), "{}", eval_err(&lua, "yaml.decode(bomb)"));
        assert!(!eval_err(&lua, r#"yaml.decode("a: [")"#).is_empty());
        let huge = eval_err(&lua, &format!("yaml.decode(string.rep('x', {}))", MAX_YAML_BYTES + 1));
        assert!(huge.contains("at most 4 MB"), "{huge}");
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
        let encoded: String = lua.load(r#"return vault("github", "base64")"#).eval().unwrap();
        assert_eq!(encoded, "{{vault:github|base64}}");
        assert!(eval_err(&lua, r#"vault("stripe")"#).contains("permissions.vault"));
        assert!(eval_err(&lua, r#"vault("github", "hex")"#).contains("unknown vault encoding"));
    }

    #[test]
    fn vault_patterns_cover_one_part() {
        let lua = lua_with(Permissions {
            vault: vec!["github/*".into()],
            ..Permissions::default()
        });
        let value: String = lua.load(r#"return vault("github/" .. "work")"#).eval().unwrap();
        assert_eq!(value, "{{vault:github/work}}");
        assert!(eval_err(&lua, r#"vault("github")"#).contains("permissions.vault"));
        assert!(eval_err(&lua, r#"vault("github/work/token")"#).contains("permissions.vault"));
        for name in ["github/*", "github/Work", "github/../x"] {
            let err = eval_err(&lua, &format!("vault({name:?})"));
            assert!(err.contains("not a valid vault key name"), "{name}: {err}");
        }
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
