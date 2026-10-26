use anyhow::Result;
use mlua::chunk::{AsChunk, Chunk, ChunkMode};
use mlua::{Lua, LuaOptions, StdLib, Table, Value};

fn safe_libs() -> StdLib {
    StdLib::TABLE | StdLib::STRING | StdLib::MATH | StdLib::UTF8 | StdLib::COROUTINE
}

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

pub fn load_source<'a>(lua: &Lua, source: impl AsChunk + 'a, name: String) -> Chunk<'a> {
    lua.load(source).set_name(name).set_mode(ChunkMode::Text)
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

    #[test]
    fn runs_lua_5_5_as_the_guide_says() {
        let lua = new_lua().unwrap();
        let result: String = lua
            .load(r#"return _VERSION .. " " .. tostring(math.pow) .. " " .. 2 ^ 3 .. " " .. math.log(100, 10)"#)
            .eval()
            .unwrap();
        assert_eq!(result, "Lua 5.5 nil 8.0 2.0");
        let err = lua.load("for i = 1, 2 do i = 5 end").exec().unwrap_err();
        assert!(err.to_string().contains('i'), "{err}");
    }

    #[test]
    fn bytecode_is_refused() {
        let lua = new_lua().unwrap();
        let bytecode = lua.load("return 1").into_function().unwrap().dump(false);
        let compiled = load_source(&lua, &bytecode, "=t".into()).into_function();
        assert!(compiled.unwrap_err().to_string().contains("binary chunk"));
        let evaluated = load_source(&lua, &bytecode, "=t".into()).eval::<Value>();
        assert!(evaluated.unwrap_err().to_string().contains("binary chunk"));
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
