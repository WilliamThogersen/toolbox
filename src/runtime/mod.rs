mod api;
mod encoding;
mod exec;
mod fs;
mod http;
mod limits;
mod modules;
mod prompt;
mod sandbox;
mod time;

use std::io::Read;
use std::rc::Rc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use mlua::serde::SerializeOptions;
use mlua::{Function, Lua, LuaSerdeExt, Value};

use crate::command::entry::Entry;
use crate::command::registry::CommandDef;
use crate::command::sources::Sources;
use crate::vault::Keys;
use crate::vault::approval::Caller;

pub fn ser_options() -> SerializeOptions {
    SerializeOptions::new()
        .serialize_none_to_null(false)
        .serialize_unit_to_null(false)
}

#[expect(clippy::needless_pass_by_value, reason = "made for `map_err`, which passes the error by value")]
fn lua_error(err: anyhow::Error) -> mlua::Error {
    mlua::Error::runtime(format!("{err:#}"))
}

const MAX_INPUT_BYTES: usize = 20 * 1024 * 1024;

fn read_capped(source: impl Read, what: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    source
        .take(MAX_INPUT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("could not read {what}"))?;
    ensure!(bytes.len() <= MAX_INPUT_BYTES, "{what} is larger than {} MB", MAX_INPUT_BYTES >> 20);
    Ok(bytes)
}

const MAX_SECONDS: f64 = 24.0 * 60.0 * 60.0;

fn seconds(secs: f64) -> Result<Duration> {
    if !(0.0..=MAX_SECONDS).contains(&secs) {
        bail!("{secs} is not a valid number of seconds (0 to {MAX_SECONDS})");
    }
    Ok(Duration::from_secs_f64(secs))
}

pub fn run(def: &CommandDef, subcommand: Option<&str>, args: &serde_json::Value, keys: Keys) -> Result<serde_json::Value> {
    let entry = def
        .manifest
        .entry(subcommand)
        .with_context(|| format!("{} has no subcommand {:?}", def.manifest.name, subcommand.unwrap_or_default()))?;
    let sources = Rc::new(Sources::read(def)?);
    let lua = sandbox::new_lua()?;
    let budget = limits::Budget::for_command(entry.limits)?;
    limits::install(&lua, budget, &entry.label())?;
    let perms = entry.permissions;
    api::install(&lua, perms)?;
    encoding::install(&lua)?;
    time::install(&lua)?;
    exec::install(&lua, perms)?;
    fs::install(&lua, &Rc::new(fs::FsGuard::new(perms)))?;
    modules::install(&lua, &sources)?;
    prompt::install(&lua, perms.terminal, &entry.label())?;
    let caller = Caller::new(def, &entry, &sources);
    http::install(&lua, &Rc::new(http::HttpClient::new(perms, caller, keys)))?;
    let files = sources.paths();
    let main = load_entry(&lua, &entry, &sources, &budget)?;
    let result: Value = main
        .call(lua.to_value_with(args, ser_options())?)
        .map_err(|err| explain(&err, &budget, &files))?;
    lua.from_value(result)
        .context("the command returned a value that cannot be turned into JSON")
}

pub fn check_syntax(def: &CommandDef) -> Result<()> {
    compile(def, |path| format!("@{}", def.dir.join(path).display()))
}

pub fn check_syntax_as(def: &CommandDef, folder: &str) -> Result<()> {
    compile(def, |path| format!("@{folder}{path}"))
}

fn compile(def: &CommandDef, chunk: impl Fn(&str) -> String) -> Result<()> {
    let lua = sandbox::new_lua()?;
    let sources = Sources::read(def)?;
    for (path, text) in sources.files() {
        sandbox::load_source(&lua, text, chunk(path)).into_function()?;
    }
    Ok(())
}

fn load_entry(lua: &Lua, entry: &Entry, sources: &Sources, budget: &limits::Budget) -> Result<Function> {
    let script = entry.script();
    let text = sources.get(&script).with_context(|| format!("missing {script}"))?;
    let returned: Value = sandbox::load_source(lua, text, format!("@{script}"))
        .eval()
        .map_err(|err| explain(&err, budget, &sources.paths()))?;
    match returned {
        Value::Function(main) => Ok(main),
        other => bail!(
            "{script} must end with `return function(args) ... end`, but it returned {}",
            other.type_name()
        ),
    }
}

fn explain(err: &mlua::Error, budget: &limits::Budget, files: &[&str]) -> anyhow::Error {
    if err.to_string().contains("not enough memory") {
        anyhow!(budget.memory_message())
    } else {
        tidy(err, files)
    }
}

fn tidy(err: &mlua::Error, files: &[&str]) -> anyhow::Error {
    let text = err.to_string();
    let (message, trace) = text.split_once("\nstack traceback:").unwrap_or((&text, ""));
    let message = message.trim_start_matches("runtime error: ").trim_end();
    let place = trace.lines().find_map(|frame| place_in(frame.trim_start(), files));
    let placed = files.iter().any(|file| message.contains(&format!("{file}:")));
    match place {
        Some(place) if !placed => anyhow!("{message} (at {place})"),
        _ => anyhow!("{message}"),
    }
}

fn place_in(frame: &str, files: &[&str]) -> Option<String> {
    files.iter().find_map(|file| {
        let line = frame.strip_prefix(file)?.strip_prefix(':')?.split(':').next()?;
        line.parse::<u32>().ok().map(|line| format!("{file}:{line}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::manifest::Manifest;
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

    #[test]
    fn reads_stop_one_byte_past_the_limit() {
        let at = read_capped(std::io::repeat(b'x').take(MAX_INPUT_BYTES as u64), "x").unwrap();
        assert_eq!(at.len(), MAX_INPUT_BYTES);
        let err = read_capped(std::io::repeat(b'x'), "stdin").unwrap_err();
        assert_eq!(err.to_string(), "stdin is larger than 20 MB");
    }

    fn no_keys() -> Keys {
        Keys {
            store: Box::new(MemoryStore::new(VaultData::default())),
            log: Box::new(crate::vault::log::MemoryLog::new()),
            tokens: crate::vault::oauth::TokenCache { dir: std::env::temp_dir().join("toolbox-unused-token-cache") },
        }
    }

    #[expect(clippy::needless_pass_by_value, reason = "tests pass `json!(...)` values as they are")]
    fn run_script(script: &str, args: serde_json::Value) -> Result<serde_json::Value> {
        let (_tmp, def) = command(script);
        run(&def, None, &args, no_keys())
    }

    #[test]
    fn errors_in_a_lib_file_say_which_file() {
        let (tmp, def) = command("local m = require('m')\nreturn function(args) return m[args.how]() end");
        std::fs::create_dir(tmp.path().join("lib")).unwrap();
        std::fs::write(tmp.path().join("lib/m.lua"), "return {\n  thrown = function() error('broke', 0) end,\n  bug = function() return nil .. 1 end,\n}").unwrap();
        let failed = |how: &str| format!("{:#}", run(&def, None, &serde_json::json!({ "how": how }), no_keys()).unwrap_err());
        assert_eq!(failed("thrown"), "broke (at lib/m.lua:2)");
        assert!(failed("bug").starts_with("lib/m.lua:3: attempt to concatenate"), "{}", failed("bug"));
    }

    #[test]
    fn a_group_runs_the_script_of_the_subcommand_asked_for() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.lua"), "return function() return 'a' end").unwrap();
        std::fs::write(tmp.path().join("b.lua"), "return 5").unwrap();
        let source = r#"{"name":"g","description":"g","subcommands":{"a":{"description":"a"},"b":{"description":"b"}}}"#;
        let def = CommandDef { manifest: Manifest::parse(source).unwrap(), manifest_source: source.to_string(), dir: tmp.path().to_path_buf() };
        assert_eq!(run(&def, Some("a"), &serde_json::json!({}), no_keys()).unwrap(), serde_json::json!("a"));
        let err = run(&def, Some("b"), &serde_json::json!({}), no_keys()).unwrap_err().to_string();
        assert!(err.starts_with("b.lua must end with `return function"), "{err}");
        let err = run(&def, None, &serde_json::json!({}), no_keys()).unwrap_err().to_string();
        assert_eq!(err, "g has no subcommand \"\"");
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
    fn errors_skip_the_traceback_but_say_where() {
        let thrown = run_script(r#"return function() error("PR not found", 0) end"#, serde_json::json!({}));
        let text = format!("{:#}", thrown.unwrap_err());
        assert!(!text.contains("stack traceback"), "{text}");
        assert!(!text.contains("runtime error"), "{text}");
        assert!(text.starts_with("PR not found (at run.lua:1)"), "{text}");

        let bug = run_script("return function()\n  local x = nil\n  return x.y\nend", serde_json::json!({}));
        let text = format!("{:#}", bug.unwrap_err());
        assert!(text.starts_with("run.lua:3: attempt to index"), "{text}");
        assert!(!text.contains('/') && !text.contains("stack traceback"), "{text}");

        let api = run_script(r#"return function() return http.get("https://x.test/") end"#, serde_json::json!({}));
        let text = format!("{:#}", api.unwrap_err());
        assert!(text.contains("permissions.http") && text.ends_with("(at run.lua:1)"), "{text}");
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
