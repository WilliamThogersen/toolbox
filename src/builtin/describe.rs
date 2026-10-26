use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;

use crate::command::manifest::Manifest;
use crate::command::origin::{Origin, origin};
use crate::command::registry::{Problem, Registry};

pub const GUIDE: &str = include_str!("../../docs/writing-commands.md");

#[derive(Debug, Serialize)]
pub struct Description<'a> {
    pub toolbox_version: &'static str,
    pub commands_dir: String,
    pub commands: Vec<&'a Manifest>,
    pub broken: &'a [Problem],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origins: Option<BTreeMap<String, Origin>>,
    pub next: &'static str,
}

pub fn describe<'a>(registry: &'a Registry, commands_dir: &Path, with_origins: bool) -> Description<'a> {
    Description {
        toolbox_version: env!("CARGO_PKG_VERSION"),
        commands_dir: commands_dir.display().to_string(),
        commands: registry.commands.iter().map(|def| &def.manifest).collect(),
        broken: &registry.problems,
        origins: with_origins.then(|| origins(registry, commands_dir)),
        next: "Run `tb self guide` to learn how to add a command. Run `tb self vault list` to see which API keys exist.",
    }
}

fn origins(registry: &Registry, commands_dir: &Path) -> BTreeMap<String, Origin> {
    let loaded = registry.commands.iter().map(|def| (def.manifest.name.clone(), def.dir.clone()));
    let broken = registry
        .problems
        .iter()
        .map(|problem| (problem.command.clone(), commands_dir.join(&problem.command)))
        .filter(|(_, dir)| dir.is_dir());
    loaded.chain(broken).map(|(name, dir)| (name, origin(&dir))).collect()
}
