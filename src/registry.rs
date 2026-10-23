//! Finds command folders on disk and loads the valid ones.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::manifest::Manifest;

pub const MANIFEST_FILE: &str = "command.json";
pub const SCRIPT_FILE: &str = "run.lua";

#[derive(Debug, Clone)]
pub struct CommandDef {
    pub manifest: Manifest,
    /// The exact `command.json` text `manifest` was parsed from.
    pub manifest_source: String,
    pub dir: PathBuf,
}

impl CommandDef {
    pub fn script_path(&self) -> PathBuf {
        self.dir.join(SCRIPT_FILE)
    }

    pub fn read_script(&self) -> Result<String> {
        let path = self.script_path();
        fs::read_to_string(&path).with_context(|| format!("could not read {}", path.display()))
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Problem {
    pub command: String,
    pub problem: String,
}

#[derive(Debug, Default)]
pub struct Registry {
    pub commands: Vec<CommandDef>,
    pub problems: Vec<Problem>,
}

impl Registry {
    pub fn find(&self, name: &str) -> Option<&CommandDef> {
        self.commands.iter().find(|c| c.manifest.name == name)
    }
}

/// Loads every `<dir>/<name>/command.json`. Broken commands are reported, not loaded.
pub fn load(dir: &Path) -> Result<Registry> {
    if !dir.exists() {
        return Ok(Registry::default());
    }
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .with_context(|| format!("could not read {}", dir.display()))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.is_dir())
        .collect();
    entries.sort();

    let (commands, problems) = entries.iter().map(|path| load_one(path)).fold(
        (Vec::new(), Vec::new()),
        |(mut commands, mut problems), result| {
            match result {
                Ok(def) => commands.push(def),
                Err(found) => problems.extend(found),
            }
            (commands, problems)
        },
    );
    Ok(Registry { commands, problems })
}

fn load_one(dir: &Path) -> std::result::Result<CommandDef, Vec<Problem>> {
    let folder = dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    load_command(dir, &folder)
}

/// Loads one command folder whose manifest `name` must equal `folder`.
pub fn load_command(dir: &Path, folder: &str) -> std::result::Result<CommandDef, Vec<Problem>> {
    let problem = |message: String| Problem {
        command: folder.to_string(),
        problem: message,
    };

    let raw = fs::read_to_string(dir.join(MANIFEST_FILE))
        .map_err(|e| vec![problem(format!("cannot read {MANIFEST_FILE}: {e}"))])?;
    let manifest = Manifest::parse(&raw).map_err(|e| vec![problem(format!("{e:#}"))])?;

    let mut problems: Vec<Problem> = manifest.validate(folder).into_iter().map(problem).collect();
    if !dir.join(SCRIPT_FILE).is_file() {
        problems.push(problem(format!("missing {SCRIPT_FILE}")));
    }
    if problems.is_empty() {
        Ok(CommandDef {
            manifest,
            manifest_source: raw,
            dir: dir.to_path_buf(),
        })
    } else {
        Err(problems)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_command(root: &Path, folder: &str, manifest: &str, script: Option<&str>) {
        let dir = root.join(folder);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(MANIFEST_FILE), manifest).unwrap();
        if let Some(src) = script {
            fs::write(dir.join(SCRIPT_FILE), src).unwrap();
        }
    }

    #[test]
    fn missing_dir_is_empty() {
        let registry = load(Path::new("/definitely/not/here")).unwrap();
        assert!(registry.commands.is_empty());
        assert!(registry.problems.is_empty());
    }

    #[test]
    fn loads_good_and_reports_broken() {
        let tmp = tempfile::tempdir().unwrap();
        write_command(
            tmp.path(),
            "hello",
            r#"{"name":"hello","description":"hi"}"#,
            Some("return function() end"),
        );
        write_command(tmp.path(), "noscript", r#"{"name":"noscript","description":"x"}"#, None);
        write_command(tmp.path(), "badjson", "{", Some(""));

        let registry = load(tmp.path()).unwrap();
        assert_eq!(registry.commands.len(), 1);
        assert!(registry.find("hello").is_some());
        assert!(registry.find("noscript").is_none());

        let broken: Vec<&str> = registry.problems.iter().map(|p| p.command.as_str()).collect();
        assert_eq!(broken, vec!["badjson", "noscript"]);
    }
}
