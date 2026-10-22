//! `exec(program, args, opts)`: runs a program listed in `permissions.exec`, without a shell.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use mlua::{Lua, LuaSerdeExt, Value};
use serde::Deserialize;

use super::api::denied;
use super::{lua_error, seconds};

/// How often a program with a timeout is checked for having finished.
const POLL: Duration = Duration::from_millis(10);

/// The optional third argument of `exec`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecOptions {
    /// Text written to the program's stdin. Without it, stdin is empty.
    #[serde(default)]
    stdin: Option<String>,
    /// Folder the program runs in.
    #[serde(default)]
    cwd: Option<String>,
    /// Extra environment variables, on top of the ones toolbox was started with.
    #[serde(default)]
    env: BTreeMap<String, String>,
    /// Seconds before the program is killed and `exec` raises an error.
    #[serde(default)]
    timeout: Option<f64>,
}

struct Finished {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

pub fn install(lua: &Lua, allowed: Vec<String>) -> mlua::Result<()> {
    let exec = lua.create_function(
        move |lua, (program, args, opts): (String, Option<Vec<String>>, Option<Value>)| {
            if !allowed.contains(&program) {
                return Err(denied("exec", &program));
            }
            let options: ExecOptions = match opts {
                Some(value) => lua.from_value(value)?,
                None => ExecOptions::default(),
            };
            let done = run(&program, &args.unwrap_or_default(), options).map_err(lua_error)?;
            let result = lua.create_table()?;
            result.set("ok", done.status.success())?;
            result.set("code", done.status.code())?;
            result.set("stdout", String::from_utf8_lossy(&done.stdout).into_owned())?;
            result.set("stderr", String::from_utf8_lossy(&done.stderr).into_owned())?;
            Ok(result)
        },
    )?;
    lua.globals().set("exec", exec)
}

fn run(program: &str, args: &[String], options: ExecOptions) -> Result<Finished> {
    let limit = options.timeout.map(seconds).transpose()?;
    let mut command = Command::new(program);
    command
        .args(args)
        .envs(&options.env)
        .stdin(if options.stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(cwd) = &options.cwd {
        command.current_dir(cwd);
    }
    if limit.is_some() {
        // Its own process group, so a timeout also stops everything it started.
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("could not run {program:?}"))?;
    if let (Some(text), Some(mut pipe)) = (options.stdin, child.stdin.take()) {
        // A program may exit without reading all its input. That is its choice, not an error.
        thread::spawn(move || pipe.write_all(text.as_bytes()));
    }
    // Both pipes are drained while the program runs, so a full pipe can't block it.
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    match limit {
        Some(limit) => finish_within(child, &stdout, &stderr, limit)
            .ok_or_else(|| anyhow!("{program:?} timed out after {}s", limit.as_secs_f64())),
        None => Ok(Finished {
            status: child.wait().with_context(|| format!("could not wait for {program:?}"))?,
            stdout: stdout.recv().unwrap_or_default(),
            stderr: stderr.recv().unwrap_or_default(),
        }),
    }
}

/// Reads a pipe to the end on its own thread. The result arrives once every process
/// holding the pipe, including background children, has closed it.
fn drain(pipe: Option<impl Read + Send + 'static>) -> Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(mut pipe) = pipe {
            // A read error ends the output early; what arrived so far is still returned.
            let _ = pipe.read_to_end(&mut bytes);
        }
        // After a timeout nobody is listening any more.
        let _ = tx.send(bytes);
    });
    rx
}

/// Waits until the program has exited and its output is complete, at most `limit`.
/// On timeout it kills the program's whole process group and returns `None`.
fn finish_within(
    mut child: Child,
    stdout: &Receiver<Vec<u8>>,
    stderr: &Receiver<Vec<u8>>,
    limit: Duration,
) -> Option<Finished> {
    let deadline = Instant::now() + limit;
    let left = || deadline.saturating_duration_since(Instant::now());
    let finished = (|| {
        let status = loop {
            if let Some(status) = child.try_wait().ok()? {
                break status;
            }
            if Instant::now() >= deadline {
                return None;
            }
            thread::sleep(POLL.min(left()));
        };
        Some(Finished {
            status,
            stdout: stdout.recv_timeout(left()).ok()?,
            stderr: stderr.recv_timeout(left()).ok()?,
        })
    })();
    if finished.is_none() {
        kill_group(&child);
        // Reaps the program if it was still running, so it doesn't linger as a zombie.
        let _ = child.wait();
    }
    finished
}

/// Kills the program and everything it started, which share its process group.
fn kill_group(child: &Child) {
    let group = child.id() as libc::pid_t;
    // SAFETY: kill(2) takes no pointers. A negative pid targets the process group the
    // program leads (`process_group(0)`). It fails only when that group is already gone.
    unsafe {
        libc::kill(-group, libc::SIGKILL);
    }
}

#[cfg(test)]
mod tests {
    use mlua::Table;

    use super::*;
    use crate::runtime::sandbox::new_lua;

    fn lua_with(allowed: &[&str]) -> Lua {
        let lua = new_lua().unwrap();
        install(&lua, allowed.iter().map(|s| s.to_string()).collect()).unwrap();
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
        // The shell exits at once, but its background child holds stdout open.
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
    fn bad_options_are_errors() {
        let lua = lua_with(&["echo"]);
        let unknown = lua.load(r#"exec("echo", {}, { shell = true })"#).exec().unwrap_err();
        assert!(unknown.to_string().contains("unknown field"), "{unknown}");
        let negative = lua.load(r#"exec("echo", {}, { timeout = -1 })"#).exec().unwrap_err();
        assert!(negative.to_string().contains("not a valid number of seconds"), "{negative}");
    }
}
