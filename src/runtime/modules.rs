use std::rc::Rc;

use anyhow::Result;
use mlua::{Lua, Table, Value};

use super::sandbox;
use crate::command::sources::{LIB_DIR, Sources, lib_path};

const LOADED: &str = "toolbox.loaded";
const LOADING: &str = "toolbox.loading";

pub fn install(lua: &Lua, sources: &Rc<Sources>) -> Result<()> {
    lua.set_named_registry_value(LOADED, lua.create_table()?)?;
    lua.set_named_registry_value(LOADING, lua.create_table()?)?;
    let sources = Rc::clone(sources);
    let require = lua.create_function(move |lua, module: String| require(lua, &sources, &module))?;
    lua.globals().set("require", require)?;
    Ok(())
}

fn require(lua: &Lua, sources: &Sources, module: &str) -> mlua::Result<Value> {
    let loaded: Table = lua.named_registry_value(LOADED)?;
    let done: Value = loaded.raw_get(module)?;
    if !done.is_nil() {
        return Ok(done);
    }
    let path = lib_path(module).ok_or_else(|| {
        mlua::Error::runtime(format!(
            "require({module:?}): a module name is a-z, 0-9, '-' and '_', and loads {LIB_DIR}/<name>.lua from this command's own folder"
        ))
    })?;
    let text = sources
        .get(&path)
        .ok_or_else(|| mlua::Error::runtime(format!("require({module:?}): this command has no {path}")))?;
    let loading: Table = lua.named_registry_value(LOADING)?;
    if loading.raw_get::<bool>(module)? {
        return Err(mlua::Error::runtime(format!("require({module:?}): {path} requires itself, through other modules or directly")));
    }
    loading.raw_set(module, true)?;
    let returned = sandbox::load_source(lua, text, format!("@{path}")).call::<Value>(());
    loading.raw_set(module, Value::Nil)?;
    let value = match returned? {
        Value::Nil => Value::Boolean(true),
        value => value,
    };
    loaded.raw_set(module, &value)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::command::manifest::Manifest;

    fn lua_with(files: &[(&str, &str)]) -> (tempfile::TempDir, Lua) {
        let tmp = tempfile::tempdir().unwrap();
        for (path, text) in [("run.lua", "return function() end")].iter().chain(files) {
            let file = tmp.path().join(path);
            fs::create_dir_all(file.parent().unwrap()).unwrap();
            fs::write(file, text).unwrap();
        }
        let manifest = Manifest::parse(r#"{"name":"t","description":"t"}"#).unwrap();
        let sources = Sources::read_in(tmp.path(), &manifest).unwrap();
        let lua = sandbox::new_lua().unwrap();
        install(&lua, &Rc::new(sources)).unwrap();
        (tmp, lua)
    }

    fn error_of(lua: &Lua, code: &str) -> String {
        lua.load(code).exec().unwrap_err().to_string()
    }

    #[test]
    fn a_module_runs_once_and_its_value_is_shared() {
        let (_tmp, lua) = lua_with(&[("lib/count.lua", "RUNS = (RUNS or 0) + 1\nreturn { n = RUNS }"), ("lib/nothing.lua", "X = 1")]);
        let same: bool = lua.load(r#"return require("count") == require("count")"#).eval().unwrap();
        assert!(same);
        assert_eq!(lua.load("return RUNS").eval::<i64>().unwrap(), 1);
        assert!(lua.load(r#"return require("nothing")"#).eval::<bool>().unwrap());
    }

    #[test]
    fn modules_can_require_each_other_but_not_in_a_loop() {
        let (_tmp, lua) = lua_with(&[
            ("lib/a.lua", r#"return { b = require("b") }"#),
            ("lib/b.lua", "return 2"),
            ("lib/self.lua", r#"return require("other")"#),
            ("lib/other.lua", r#"return require("self")"#),
        ]);
        assert_eq!(lua.load(r#"return require("a").b"#).eval::<i64>().unwrap(), 2);
        let err = error_of(&lua, r#"require("self")"#);
        assert!(err.contains("lib/self.lua requires itself"), "{err}");
    }

    #[test]
    fn a_failed_module_can_be_required_again() {
        let (_tmp, lua) = lua_with(&[("lib/flaky.lua", "TRIES = (TRIES or 0) + 1\nif TRIES == 1 then error('first try') end\nreturn 'ok'")]);
        let err = error_of(&lua, r#"require("flaky")"#);
        assert!(err.contains("lib/flaky.lua:2: first try"), "{err}");
        assert_eq!(lua.load(r#"return require("flaky")"#).eval::<String>().unwrap(), "ok");
    }

    #[test]
    fn only_this_commands_lib_files_load() {
        let (_tmp, lua) = lua_with(&[("lib/store.lua", "return 1"), ("helper.lua", "return 2")]);
        for (module, says) in [
            ("helper", "this command has no lib/helper.lua"),
            ("../run", "a module name is a-z"),
            ("lib/store", "a module name is a-z"),
            ("store.lua", "a module name is a-z"),
        ] {
            let err = error_of(&lua, &format!("require({module:?})"));
            assert!(err.contains(says), "{module}: {err}");
        }
        assert!(lua.load("return package == nil").eval::<bool>().unwrap());
    }
}
