//! What one run may use: memory for Lua values, and CPU time. A runaway script
//! (`while true do end`, a table that grows forever) ends with an error instead of
//! running until someone kills it. A command that needs more says so in its
//! `command.json` under `limits`.

use std::cell::Cell;
use std::time::Duration;

use anyhow::Result;
use mlua::{HookTriggers, Lua, VmState};

use crate::manifest::Limits;

pub const DEFAULT_CPU_SECONDS: f64 = 60.0;
pub const DEFAULT_MEMORY_MB: u64 = 512;

/// Lua instructions between two looks at the CPU time. A C function like
/// `string.rep` counts as one instruction, however long it runs.
const CHECK_EVERY: u32 = 10_000;

/// The limits one run gets: the command's own, or the defaults.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Budget {
    /// CPU time the script may use. Waiting for `http` or `exec` uses none.
    pub cpu: Duration,
    /// Memory for Lua values, in MB.
    pub memory_mb: u64,
}

impl Budget {
    /// `Manifest::validate` already checked the numbers, so commands with bad limits never run.
    pub fn for_command(limits: &Limits) -> Result<Self> {
        let cpu = super::seconds(limits.cpu_seconds.unwrap_or(DEFAULT_CPU_SECONDS))?;
        let memory_mb = limits.memory_mb.unwrap_or(DEFAULT_MEMORY_MB);
        Ok(Self { cpu, memory_mb })
    }

    /// The error for a script that ran out of memory.
    pub fn memory_message(&self) -> String {
        format!(
            "the script used more than {} MB of memory. If it needs more, raise limits.memory_mb in its command.json",
            self.memory_mb
        )
    }

    fn cpu_message(&self) -> String {
        format!(
            "the script used more than {}s of CPU time. If it needs more, raise limits.cpu_seconds in its command.json",
            self.cpu.as_secs_f64()
        )
    }
}

/// Caps Lua's memory and checks its CPU time as it runs, in coroutines too: a global
/// hook is copied into every coroutine the script creates. Past the CPU limit the
/// script gets an error. If it catches that (`pcall`) and keeps going, the next check
/// ends the whole process, which no Lua code can catch.
pub fn install(lua: &Lua, budget: Budget, command: &str) -> Result<()> {
    let bytes = usize::try_from(budget.memory_mb.saturating_mul(1024 * 1024)).unwrap_or(usize::MAX);
    lua.set_memory_limit(bytes)?;
    let start = thread_cpu_time();
    let message = budget.cpu_message();
    let command = command.to_string();
    let warned = Cell::new(false);
    lua.set_global_hook(HookTriggers::new().every_nth_instruction(CHECK_EVERY), move |_, _| {
        if thread_cpu_time().saturating_sub(start) < budget.cpu {
            return Ok(VmState::Continue);
        }
        if warned.replace(true) {
            crate::cli::report_error(&format!("command {command:?} failed: {message}"));
            std::process::exit(1);
        }
        Err(mlua::Error::runtime(message.clone()))
    })?;
    Ok(())
}

/// CPU time the calling thread has used. Lua and its hook run on one thread, so
/// other threads (and other tests) don't count.
fn thread_cpu_time() -> Duration {
    let mut now = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: clock_gettime only writes the timespec it is given. It can't fail for
    // this clock on macOS or Linux; if it did, the time would read as zero.
    unsafe {
        libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut now);
    }
    Duration::new(now.tv_sec as u64, now.tv_nsec as u32)
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::runtime::sandbox::new_lua;

    fn lua_with(cpu: Duration, memory_mb: u64) -> Lua {
        let lua = new_lua().unwrap();
        install(&lua, Budget { cpu, memory_mb }, "t").unwrap();
        lua
    }

    #[test]
    fn endless_loops_stop_at_the_cpu_limit_in_coroutines_too() {
        for script in ["while true do end", "coroutine.wrap(function() while true do end end)()"] {
            let lua = lua_with(Duration::from_millis(200), 64);
            let started = Instant::now();
            let err = lua.load(script).exec().unwrap_err();
            assert!(err.to_string().contains("more than 0.2s of CPU time"), "{script}: {err}");
            assert!(started.elapsed() < Duration::from_secs(5), "{script}");
        }
    }

    #[test]
    fn runaway_tables_stop_at_the_memory_limit() {
        let lua = lua_with(Duration::from_secs(3600), 16);
        let err = lua.load("local t = {} for i = 1, 1e9 do t[i] = i end").exec().unwrap_err();
        assert!(err.to_string().contains("not enough memory"), "{err}");
    }

    #[test]
    fn normal_scripts_run_untouched() {
        let lua = lua_with(Duration::from_secs(3600), 64);
        let sum: i64 = lua.load("local s = 0 for i = 1, 1e6 do s = s + i end return s").eval().unwrap();
        assert_eq!(sum, 500_000_500_000);
    }

    #[test]
    fn commands_get_the_defaults_unless_they_ask_for_more() {
        let defaults = Budget::for_command(&Limits::default()).unwrap();
        assert_eq!(defaults, Budget { cpu: Duration::from_secs(60), memory_mb: 512 });
        let more = Limits { cpu_seconds: Some(300.0), memory_mb: Some(2048) };
        assert_eq!(Budget::for_command(&more).unwrap(), Budget { cpu: Duration::from_secs(300), memory_mb: 2048 });
    }
}
