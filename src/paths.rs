use std::path::PathBuf;

use anyhow::{Context, Result};

/// Root folder for toolbox data: `$TOOLBOX_HOME`, or `~/.toolbox`.
pub fn toolbox_home() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("TOOLBOX_HOME") {
        return Ok(PathBuf::from(dir));
    }
    dirs::home_dir()
        .map(|home| home.join(".toolbox"))
        .context("could not find the home directory; set TOOLBOX_HOME")
}

pub fn commands_dir() -> Result<PathBuf> {
    Ok(toolbox_home()?.join("commands"))
}

/// Saved marketplaces (`tb self market`).
pub fn markets_file() -> Result<PathBuf> {
    Ok(toolbox_home()?.join("markets.json"))
}
