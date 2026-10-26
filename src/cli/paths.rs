use std::path::PathBuf;

use anyhow::{Context, Result};

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

pub fn markets_file() -> Result<PathBuf> {
    Ok(toolbox_home()?.join("markets.json"))
}

pub fn claude_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("CLAUDE_CONFIG_DIR") {
        return Ok(PathBuf::from(dir));
    }
    dirs::home_dir()
        .map(|home| home.join(".claude"))
        .context("could not find the home directory; set CLAUDE_CONFIG_DIR")
}
