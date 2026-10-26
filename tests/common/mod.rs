//! Helpers every end-to-end test file uses.
#![expect(unsafe_code, reason = "starting `tb` without a terminal needs setsid between fork and exec")]

use std::fs;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Starts `cmd` in a session of its own, with no controlling terminal, like an AI agent's shell.
pub fn detach(cmd: &mut Command) -> &mut Command {
    let new_session = || {
        // SAFETY: setsid takes no arguments and touches no memory. It only fails when the
        // child already leads a group, and then it has no terminal either.
        let _ = unsafe { libc::setsid() };
        Ok(())
    };
    // SAFETY: `new_session` runs between fork and exec, where only async-signal-safe calls
    // are allowed. setsid is one, and `new_session` allocates nothing.
    unsafe { cmd.pre_exec(new_session) }
}

/// A script that runs `sleep 30` through `exec` with its own `timeout`, which puts it in a process
/// group of its own, after writing its pid to `pid_file`.
#[allow(dead_code, reason = "not every test file starts one")]
pub fn exec_sleeper_script(pid_file: &Path) -> String {
    format!(
        r#"return function() return exec("sh", {{"-c", "echo $$ > '{}'; exec sleep 30"}}, {{ timeout = 60 }}) end"#,
        pid_file.display()
    )
}

/// The pid `exec_sleeper_script` wrote, once it has.
#[allow(dead_code, reason = "not every test file starts one")]
pub fn read_pid(pid_file: &Path) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(pid) = fs::read_to_string(pid_file).ok().and_then(|text| text.trim().parse().ok()) {
            return pid;
        }
        assert!(Instant::now() < deadline, "the exec'd program never started");
        thread::sleep(Duration::from_millis(20));
    }
}

/// Whether `pid` is gone (or a zombie waiting to be reaped) within a few seconds.
#[allow(dead_code, reason = "not every test file starts one")]
pub fn ends_soon(pid: u32) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        let out = Command::new("ps").args(["-o", "stat=", "-p", &pid.to_string()]).stderr(Stdio::null()).output().unwrap();
        let state = String::from_utf8_lossy(&out.stdout);
        if state.trim().is_empty() || state.trim().starts_with('Z') {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    false
}
