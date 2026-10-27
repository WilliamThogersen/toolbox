use std::process::{Command, Stdio};

use anyhow::{Context, Result};

use crate::sys;

pub fn run(mut command: Command, program: &str) -> Result<u32> {
    command.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    sys::start_new_session(&mut command);
    let child = command.spawn().with_context(|| format!("could not start {program:?}"))?;
    Ok(child.id())
}
