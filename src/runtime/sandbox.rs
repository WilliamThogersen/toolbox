//! A Lua state without file, OS or code-loading access.

use anyhow::Result;
use mlua::{Lua, LuaOptions, StdLib, Table, Value};

fn safe_libs() -> StdLib {
    StdLib::TABLE | StdLib::STRING | StdLib::MATH | StdLib::UTF8 | StdLib::COROUTINE
}

/// Base-library functions that read files or load (possibly binary) chunks.
const REMOVED_GLOBALS: &[&str] = &["dofile", "loadfile", "load", "require"];

pub fn new_lua() -> Result<Lua> {
    let lua = Lua::new_with(safe_libs(), LuaOptions::default())?;
    let globals = lua.globals();
    for name in REMOVED_GLOBALS {
        globals.set(*name, Value::Nil)?;
    }
    let string: Table = globals.get("string")?;
    string.set("dump", Value::Nil)?;
    Ok(lua)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dangerous_globals_are_gone() {
        let lua = new_lua().unwrap();
        let missing: bool = lua
            .load("return io == nil and os == nil and load == nil and dofile == nil and loadfile == nil and require == nil and debug == nil and package == nil and string.dump == nil")
            .eval()
            .unwrap();
        assert!(missing);
    }

    /// `tb self guide` promises Lua 5.5 and tells authors these replacements work.
    #[test]
    fn runs_lua_5_5_as_the_guide_says() {
        let lua = new_lua().unwrap();
        let result: String = lua
            .load(r#"return _VERSION .. " " .. tostring(math.pow) .. " " .. 2 ^ 3 .. " " .. math.log(100, 10)"#)
            .eval()
            .unwrap();
        assert_eq!(result, "Lua 5.5 nil 8.0 2.0");
        let err = lua.load("for i = 1, 2 do i = 5 end").exec().unwrap_err();
        assert!(err.to_string().contains("i"), "{err}");
    }

    #[test]
    fn safe_libs_work() {
        let lua = new_lua().unwrap();
        let result: String = lua
            .load(r#"return string.upper("ok") .. table.concat({1, 2}, ",") .. math.floor(2.7)"#)
            .eval()
            .unwrap();
        assert_eq!(result, "OK1,22");
    }
}
