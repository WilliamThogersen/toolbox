//! `tb check`: manifest problems plus Lua syntax errors, in one report.

use serde::Serialize;

use crate::registry::{Problem, Registry};
use crate::runtime;

#[derive(Debug, Serialize)]
pub struct CheckReport {
    pub ok: bool,
    pub commands: Vec<String>,
    pub problems: Vec<Problem>,
}

pub fn check(registry: &Registry) -> CheckReport {
    let syntax_problems = registry.commands.iter().filter_map(|def| {
        runtime::check_syntax(def).err().map(|err| Problem {
            command: def.manifest.name.clone(),
            problem: format!("{err:#}"),
        })
    });
    let problems: Vec<Problem> = registry.problems.iter().cloned().chain(syntax_problems).collect();
    let commands = registry
        .commands
        .iter()
        .map(|def| def.manifest.name.clone())
        .filter(|name| !problems.iter().any(|p| p.command == *name))
        .collect();
    CheckReport {
        ok: problems.is_empty(),
        commands,
        problems,
    }
}
