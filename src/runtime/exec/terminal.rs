use std::io::{self, IsTerminal};
use std::os::fd::AsFd;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, ensure};

use super::wait_within;
use crate::sys;

pub const LONGEST_WAIT: Duration = Duration::from_hours(24);

pub fn run(mut command: Command, program: &str, limit: Option<Duration>) -> Result<ExitStatus> {
    ensure!(
        io::stdin().is_terminal() && io::stderr().is_terminal(),
        "exec with terminal = true needs a person at a terminal, and this run has none. Ask the user to run the command in their own terminal"
    );
    let screen = io::stderr()
        .as_fd()
        .try_clone_to_owned()
        .context("could not reach the terminal")?;
    command.stdin(Stdio::inherit()).stdout(Stdio::from(screen)).stderr(Stdio::inherit());
    let mut child = command.spawn().with_context(|| format!("could not run {program:?}"))?;
    let _interrupts_go_to_the_program = sys::InterruptsIgnored::new();
    let limit = limit.unwrap_or(LONGEST_WAIT);
    wait_within(&mut child, Instant::now() + limit).ok_or_else(|| {
        let _ = child.kill();
        let _ = child.wait();
        anyhow!("{program:?} timed out after {}s", limit.as_secs_f64())
    })
}
