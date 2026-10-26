use std::path::Path;

use serde::Serialize;

use crate::command::manifest::Manifest;
use crate::command::registry::{Problem, Registry};

pub const GUIDE: &str = include_str!("../../docs/writing-commands.md");

#[derive(Debug, Serialize)]
pub struct Description<'a> {
    pub toolbox_version: &'static str,
    pub commands_dir: String,
    pub commands: Vec<&'a Manifest>,
    pub broken: &'a [Problem],
    pub next: &'static str,
}

pub fn describe<'a>(registry: &'a Registry, commands_dir: &Path) -> Description<'a> {
    Description {
        toolbox_version: env!("CARGO_PKG_VERSION"),
        commands_dir: commands_dir.display().to_string(),
        commands: registry.commands.iter().map(|def| &def.manifest).collect(),
        broken: &registry.problems,
        next: "Run `tb self guide` to learn how to add a command. Run `tb self vault list` to see which API keys exist.",
    }
}
