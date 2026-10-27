mod detached;
mod terminal;

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, ensure};
use mlua::{Lua, LuaSerdeExt, Table, Value};
use serde::Deserialize;

use super::api::{denied, needs_flag};
use super::{MAX_INPUT_BYTES, lua_error, seconds};
use crate::command::manifest::Permissions;
use crate::sys;

const POLL: Duration = Duration::from_millis(10);

const DEFAULT_TIMEOUT: Duration = Duration::from_mins(10);

const CODE_ENV: [&str; 6] = ["PATH", "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "PS4"];

const LOADER_ENV_PREFIXES: [&str; 2] = ["LD_", "DYLD_"];

const BASE_ENV: [&str; 8] = ["PATH", "HOME", "USER", "LOGNAME", "LANG", "TMPDIR", "TERM", "TZ"];
const BASE_ENV_PREFIX: &str = "LC_";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecOptions {
    #[serde(default)]
    stdin: Option<String>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    timeout: Option<f64>,
    #[serde(default)]
    stream: bool,
    #[serde(default)]
    terminal: bool,
    #[serde(default)]
    detach: bool,
}

struct Rules {
    programs: Vec<String>,
    env: Vec<String>,
    terminal: bool,
    background: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Mode {
    Captured,
    Terminal,
    Detached,
}

impl ExecOptions {
    fn mode(&self) -> Result<Mode> {
        match (self.terminal, self.detach) {
            (true, true) => Err(anyhow!("exec can't use terminal and detach together")),
            (true, false) => {
                ensure!(
                    self.stdin.is_none() && !self.stream,
                    "with terminal = true the program reads and writes the terminal itself, so stdin and stream don't apply"
                );
                Ok(Mode::Terminal)
            }
            (false, true) => {
                ensure!(
                    self.stdin.is_none() && !self.stream && self.timeout.is_none(),
                    "with detach = true the program runs on after the command ends, so stdin, stream and timeout don't apply"
                );
                Ok(Mode::Detached)
            }
            (false, false) => Ok(Mode::Captured),
        }
    }
}

struct Finished {
    status: ExitStatus,
    stdout: Drained,
    stderr: Drained,
}

#[derive(Default)]
struct Drained {
    bytes: Vec<u8>,
    overflowed: bool,
}

impl Drained {
    fn text(self, program: &str, stream: &str) -> Result<String> {
        ensure!(
            !self.overflowed,
            "{program:?} wrote more than {} MB to {stream}",
            MAX_INPUT_BYTES >> 20
        );
        Ok(String::from_utf8_lossy(&self.bytes).into_owned())
    }
}

pub fn install(lua: &Lua, perms: &Permissions) -> mlua::Result<()> {
    let rules = Rules {
        programs: perms.exec.clone(),
        env: perms.env.clone(),
        terminal: perms.terminal,
        background: perms.background,
    };
    let exec = lua.create_function(
        move |lua, (program, args, opts): (String, Option<Vec<String>>, Option<Value>)| {
            if !rules.programs.contains(&program) {
                return Err(denied("exec", &program));
            }
            let options: ExecOptions = match opts {
                Some(value) => lua.from_value(value)?,
                None => ExecOptions::default(),
            };
            call(lua, &rules, &program, &args.unwrap_or_default(), options)
        },
    )?;
    lua.globals().set("exec", exec)
}

fn call(lua: &Lua, rules: &Rules, program: &str, args: &[String], options: ExecOptions) -> mlua::Result<Table> {
    let result = lua.create_table()?;
    match options.mode().map_err(lua_error)? {
        Mode::Captured => {
            let done = run(program, args, options, &rules.env).map_err(lua_error)?;
            result.set("ok", done.status.success())?;
            result.set("code", done.status.code())?;
            result.set("stdout", done.stdout.text(program, "stdout").map_err(lua_error)?)?;
            result.set("stderr", done.stderr.text(program, "stderr").map_err(lua_error)?)?;
        }
        Mode::Terminal => {
            if !rules.terminal {
                return Err(needs_flag("terminal", "exec with terminal = true"));
            }
            let limit = options.timeout.map(seconds).transpose().map_err(lua_error)?;
            let command = prepared(program, args, &options, &rules.env).map_err(lua_error)?;
            let status = terminal::run(command, program, limit).map_err(lua_error)?;
            result.set("ok", status.success())?;
            result.set("code", status.code())?;
        }
        Mode::Detached => {
            if !rules.background {
                return Err(needs_flag("background", "exec with detach = true"));
            }
            let command = prepared(program, args, &options, &rules.env).map_err(lua_error)?;
            result.set("pid", detached::run(command, program).map_err(lua_error)?)?;
        }
    }
    Ok(result)
}

fn prepared(program: &str, args: &[String], options: &ExecOptions, declared_env: &[String]) -> Result<Command> {
    refuse_code_loading_env(&options.env)?;
    let mut command = Command::new(locate(program)?);
    command
        .args(args)
        .env_clear()
        .envs(env::vars_os().filter(|(name, _)| name.to_str().is_some_and(|name| inherits(name, declared_env))))
        .envs(&options.env);
    if let Some(cwd) = &options.cwd {
        command.current_dir(cwd);
    }
    Ok(command)
}

fn run(program: &str, args: &[String], options: ExecOptions, declared_env: &[String]) -> Result<Finished> {
    let own_group = options.timeout.is_some();
    let limit = time_limit(options.timeout)?;
    let mut command = prepared(program, args, &options, declared_env)?;
    command
        .stdin(if options.stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if own_group {
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("could not run {program:?}"))?;
    if let (Some(text), Some(mut pipe)) = (options.stdin, child.stdin.take()) {
        thread::spawn(move || pipe.write_all(text.as_bytes()));
    }
    let stdout = drain(child.stdout.take(), options.stream);
    let stderr = drain(child.stderr.take(), options.stream);
    let _watched = own_group.then(|| sys::WatchedGroup::new(child.id())).flatten();
    finish_within(child, &stdout, &stderr, limit).ok_or_else(|| {
        let hint = if own_group { "" } else { " (the default; set `timeout` to wait longer)" };
        anyhow!("{program:?} timed out after {}s{hint}", limit.as_secs_f64())
    })
}

fn time_limit(timeout: Option<f64>) -> Result<Duration> {
    Ok(timeout.map(seconds).transpose()?.unwrap_or(DEFAULT_TIMEOUT))
}

fn refuse_code_loading_env(vars: &BTreeMap<String, String>) -> Result<()> {
    vars.keys().try_for_each(|name| {
        ensure!(
            !name.is_empty() && !name.contains(['=', '\0']),
            "{name:?} is not a valid environment variable name"
        );
        let loads_code =
            CODE_ENV.contains(&name.as_str()) || LOADER_ENV_PREFIXES.iter().any(|prefix| name.starts_with(prefix));
        ensure!(!loads_code, "exec can't set {name}: it changes which code the program runs");
        Ok(())
    })
}

fn inherits(name: &str, declared_env: &[String]) -> bool {
    BASE_ENV.contains(&name) || name.starts_with(BASE_ENV_PREFIX) || declared_env.iter().any(|d| d == name)
}

fn locate(program: &str) -> Result<PathBuf> {
    if program.contains('/') {
        return std::path::absolute(program).with_context(|| format!("could not find {program:?}"));
    }
    let dirs = env::var_os("PATH").unwrap_or_default();
    env::split_paths(&dirs)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(program))
        .find(|candidate| is_executable(candidate))
        .ok_or_else(|| anyhow!("could not find {program:?} in PATH"))
}

fn is_executable(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

fn drain(pipe: Option<impl Read + Send + 'static>, echo: bool) -> Receiver<Drained> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut drained = Drained::default();
        if let Some(mut pipe) = pipe {
            let mut kept = Kept { bytes: &mut drained.bytes, echo };
            let _ = io::copy(&mut (&mut pipe).take(MAX_INPUT_BYTES as u64), &mut kept);
            drained.overflowed = io::copy(&mut pipe, &mut io::sink()).is_ok_and(|extra| extra > 0);
        }
        let _ = tx.send(drained);
    });
    rx
}

struct Kept<'a> {
    bytes: &'a mut Vec<u8>,
    echo: bool,
}

impl Write for Kept<'_> {
    fn write(&mut self, chunk: &[u8]) -> io::Result<usize> {
        if self.echo {
            let _ = io::stderr().lock().write_all(chunk);
        }
        self.bytes.extend_from_slice(chunk);
        Ok(chunk.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn wait_within(child: &mut Child, deadline: Instant) -> Option<ExitStatus> {
    loop {
        if let Some(status) = child.try_wait().ok()? {
            return Some(status);
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        thread::sleep(POLL.min(left));
    }
}

fn finish_within(
    mut child: Child,
    stdout: &Receiver<Drained>,
    stderr: &Receiver<Drained>,
    limit: Duration,
) -> Option<Finished> {
    let deadline = Instant::now() + limit;
    let left = || deadline.saturating_duration_since(Instant::now());
    let finished = (|| {
        let status = wait_within(&mut child, deadline)?;
        Some(Finished {
            status,
            stdout: stdout.recv_timeout(left()).ok()?,
            stderr: stderr.recv_timeout(left()).ok()?,
        })
    })();
    if finished.is_none() {
        sys::kill_process_group(child.id());
        let _ = child.kill();
        let _ = child.wait();
    }
    finished
}

#[cfg(test)]
mod tests {
    use mlua::Table;

    use super::*;
    use crate::runtime::sandbox::new_lua;

    fn lua_with(allowed: &[&str]) -> Lua {
        lua_allowed(&Permissions { exec: allowed.iter().map(std::string::ToString::to_string).collect(), ..Permissions::default() })
    }

    fn lua_allowed(perms: &Permissions) -> Lua {
        let lua = new_lua().unwrap();
        install(&lua, perms).unwrap();
        lua
    }

    #[test]
    fn exec_runs_allowed_programs_only() {
        let lua = lua_with(&["echo"]);
        let out: Table = lua.load(r#"return exec("echo", {"hi"})"#).eval().unwrap();
        assert_eq!(out.get::<String>("stdout").unwrap(), "hi\n");
        assert!(out.get::<bool>("ok").unwrap());
        let err = lua.load(r#"exec("rm", {"-rf", "/tmp/x"})"#).exec().unwrap_err();
        assert!(err.to_string().contains("permissions.exec"));
    }

    #[test]
    fn programs_without_a_timeout_get_the_default() {
        assert_eq!(time_limit(None).unwrap(), DEFAULT_TIMEOUT);
        assert_eq!(time_limit(Some(2.5)).unwrap(), Duration::from_millis(2500));
        assert!(time_limit(Some(-1.0)).is_err());
    }

    #[test]
    fn a_program_outside_its_own_group_is_still_killed_at_the_limit() {
        let mut child = Command::new("sleep").arg("30").stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let (stdout, stderr) = (drain(child.stdout.take(), false), drain(child.stderr.take(), false));
        let pid = child.id();
        let started = Instant::now();
        assert!(finish_within(child, &stdout, &stderr, Duration::from_millis(200)).is_none());
        assert!(started.elapsed() < Duration::from_secs(5));
        let alive = Command::new("kill").args(["-0", &pid.to_string()]).stderr(Stdio::null()).status().unwrap();
        assert!(!alive.success(), "sleep {pid} is still running");
    }

    #[test]
    fn output_past_the_limit_is_an_error_not_a_hang() {
        let lua = lua_with(&["head"]);
        let over = format!(r#"exec("head", {{"-c", "{}", "/dev/zero"}})"#, MAX_INPUT_BYTES + 1);
        let err = lua.load(over).exec().unwrap_err().to_string();
        assert!(err.contains("wrote more than 20 MB to stdout"), "{err}");
        let at: Table = lua.load(format!(r#"return exec("head", {{"-c", "{MAX_INPUT_BYTES}", "/dev/zero"}})"#)).eval().unwrap();
        assert_eq!(at.get::<mlua::LuaString>("stdout").unwrap().as_bytes().len(), MAX_INPUT_BYTES);
    }

    #[test]
    fn stdin_cwd_and_env_reach_the_program() {
        let lua = lua_with(&["cat", "pwd", "sh"]);
        let piped: String = lua
            .load(r#"return exec("cat", {}, { stdin = "piped text" }).stdout"#)
            .eval()
            .unwrap();
        assert_eq!(piped, "piped text");

        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().canonicalize().unwrap();
        lua.globals().set("dir", real.display().to_string()).unwrap();
        let cwd: String = lua.load(r#"return exec("pwd", {}, { cwd = dir }).stdout"#).eval().unwrap();
        assert_eq!(cwd.trim(), real.display().to_string());

        let env: String = lua
            .load(r#"return exec("sh", {"-c", "printf %s \"$TB_TEST\""}, { env = { TB_TEST = "set" } }).stdout"#)
            .eval()
            .unwrap();
        assert_eq!(env, "set");
    }

    #[test]
    fn env_cannot_change_which_code_runs() {
        let lua = lua_with(&["echo"]);
        for name in ["PATH", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "PS4"] {
            let err = lua
                .load(format!(r#"exec("echo", {{}}, {{ env = {{ {name} = "/tmp" }} }})"#))
                .exec()
                .unwrap_err();
            assert!(err.to_string().contains(&format!("can't set {name}")), "{err}");
        }
    }

    #[test]
    fn only_base_and_declared_variables_are_inherited() {
        let declared = vec!["GITHUB_TOKEN".to_string()];
        for name in ["PATH", "HOME", "LANG", "LC_ALL", "GITHUB_TOKEN"] {
            assert!(inherits(name, &declared), "{name}");
        }
        for name in ["AWS_SECRET_ACCESS_KEY", "TOOLBOX_HOME", "PATHS", "GITHUB_TOKEN_2"] {
            assert!(!inherits(name, &declared), "{name}");
        }
    }

    #[test]
    fn env_names_must_be_plain_names() {
        let lua = lua_with(&["echo"]);
        for name in [r#""PATH=/tmp/evil:""#, r#""""#, r#""A\0B""#] {
            let err = lua
                .load(format!(r#"exec("echo", {{}}, {{ env = {{ [{name}] = "x" }} }})"#))
                .exec()
                .unwrap_err();
            assert!(err.to_string().contains("not a valid environment variable name"), "{name}: {err}");
        }
    }

    #[test]
    fn programs_are_found_before_the_script_options_apply() {
        let sh = locate("sh").unwrap();
        assert!(sh.is_absolute() && sh.ends_with("sh"), "{}", sh.display());
        let relative = locate("./tool").unwrap();
        assert!(relative.starts_with(std::env::current_dir().unwrap()), "{}", relative.display());
        let err = locate("no-such-program-for-tb-tests").unwrap_err();
        assert!(err.to_string().contains("could not find"), "{err}");
    }

    #[test]
    fn timeout_kills_slow_programs() {
        let lua = lua_with(&["sleep", "echo"]);
        let started = Instant::now();
        let err = lua
            .load(r#"exec("sleep", {"5"}, { timeout = 0.2 })"#)
            .exec()
            .unwrap_err();
        assert!(err.to_string().contains("timed out after 0.2s"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(3));

        let fast: bool = lua
            .load(r#"return exec("echo", {"x"}, { timeout = 5 }).ok"#)
            .eval()
            .unwrap();
        assert!(fast);
    }

    #[test]
    fn timeout_also_stops_background_children() {
        let lua = lua_with(&["sh"]);
        let marker = tempfile::tempdir().unwrap();
        lua.globals().set("marker", marker.path().join("late").display().to_string()).unwrap();
        let started = Instant::now();
        let err = lua
            .load(r#"exec("sh", {"-c", "(sleep 1; touch '" .. marker .. "') & echo started"}, { timeout = 0.3 })"#)
            .exec()
            .unwrap_err();
        assert!(err.to_string().contains("timed out"), "{err}");
        assert!(started.elapsed() < Duration::from_millis(900), "{:?}", started.elapsed());
        thread::sleep(Duration::from_millis(1200));
        assert!(!marker.path().join("late").exists(), "the background child kept running");
    }

    #[test]
    fn huge_timeouts_are_errors_not_panics() {
        let lua = lua_with(&["true"]);
        let err = lua.load(r#"exec("true", {}, { timeout = 1e19 })"#).exec().unwrap_err();
        assert!(err.to_string().contains("not a valid number of seconds"), "{err}");
    }

    #[test]
    fn modes_need_their_permission_and_fit_together() {
        let lua = lua_with(&["sh"]);
        for (opts, says) in [
            ("{ terminal = true }", r#"exec with terminal = true needs "terminal": true"#),
            ("{ detach = true }", r#"exec with detach = true needs "background": true"#),
        ] {
            let err = lua.load(format!(r#"exec("sh", {{}}, {opts})"#)).exec().unwrap_err().to_string();
            assert!(err.contains(says), "{opts}: {err}");
        }
        let lua = lua_allowed(&Permissions { exec: vec!["sh".into()], terminal: true, background: true, ..Permissions::default() });
        for (opts, says) in [
            ("{ terminal = true, detach = true }", "terminal and detach together"),
            ("{ terminal = true, stdin = 'x' }", "stdin and stream don't apply"),
            ("{ terminal = true, stream = true }", "stdin and stream don't apply"),
            ("{ detach = true, timeout = 1 }", "stdin, stream and timeout don't apply"),
            ("{ detach = true, stream = true }", "stdin, stream and timeout don't apply"),
        ] {
            let err = lua.load(format!(r#"exec("sh", {{}}, {opts})"#)).exec().unwrap_err().to_string();
            assert!(err.contains(says), "{opts}: {err}");
        }
    }

    #[test]
    fn a_detached_program_runs_on_its_own() {
        let lua = lua_allowed(&Permissions { exec: vec!["sh".into()], background: true, ..Permissions::default() });
        let marker = tempfile::tempdir().unwrap();
        let file = marker.path().join("done");
        lua.globals().set("file", file.display().to_string()).unwrap();
        let started = Instant::now();
        let out: Table = lua
            .load(r#"return exec("sh", {"-c", "sleep 0.3; echo $$ > '" .. file .. "'"}, { detach = true })"#)
            .eval()
            .unwrap();
        assert!(started.elapsed() < Duration::from_millis(250), "detach waited for the program");
        let pid: u32 = out.get("pid").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !file.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(fs::read_to_string(&file).unwrap().trim(), pid.to_string());
    }

    #[test]
    fn bad_options_are_errors() {
        let lua = lua_with(&["echo"]);
        let unknown = lua.load(r#"exec("echo", {}, { shell = true })"#).exec().unwrap_err();
        assert!(unknown.to_string().contains("unknown field"), "{unknown}");
        let negative = lua.load(r#"exec("echo", {}, { timeout = -1 })"#).exec().unwrap_err();
        assert!(negative.to_string().contains("not a valid number of seconds"), "{negative}");
    }
}
