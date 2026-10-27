use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::command::manifest::Manifest;
use crate::command::sources::LIB_DIR;

pub const MANIFEST_FILE: &str = "command.json";
pub const SCRIPT_FILE: &str = "run.lua";

#[derive(Debug, Clone)]
pub struct CommandDef {
    pub manifest: Manifest,
    pub manifest_source: String,
    pub dir: PathBuf,
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

pub fn load_command(dir: &Path, folder: &str) -> std::result::Result<CommandDef, Vec<Problem>> {
    let problem = |message: String| Problem {
        command: folder.to_string(),
        problem: message,
    };

    let raw = fs::read_to_string(dir.join(MANIFEST_FILE))
        .map_err(|e| vec![problem(format!("cannot read {MANIFEST_FILE}: {e}"))])?;
    let manifest = Manifest::parse(&raw).map_err(|e| vec![problem(format!("{e:#}"))])?;

    let mut problems: Vec<Problem> = manifest.validate(folder).into_iter().map(problem).collect();
    problems.extend(manifest.scripts().iter().filter_map(|script| script_problem(dir, script)).map(problem));
    problems.extend(lib_problem(dir).map(problem));
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

fn script_problem(dir: &Path, script: &str) -> Option<String> {
    match dir.join(script).symlink_metadata() {
        Ok(meta) if meta.is_file() => None,
        Ok(meta) if meta.file_type().is_symlink() => Some(format!("{script} must be a plain file, not a link")),
        Ok(_) => Some(format!("{script} must be a plain file")),
        Err(_) => Some(format!("missing {script}")),
    }
}

fn lib_problem(dir: &Path) -> Option<String> {
    let meta = dir.join(LIB_DIR).symlink_metadata().ok()?;
    (!meta.is_dir()).then(|| format!("{LIB_DIR} must be a folder, not a link or a file"))
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
        write_command(
            tmp.path(),
            "group",
            r#"{"name":"group","description":"x","subcommands":{"a":{"description":"x"},"b":{"description":"x"}}}"#,
            None,
        );
        fs::write(tmp.path().join("group/a.lua"), "return function() end").unwrap();
        write_command(tmp.path(), "linked", r#"{"name":"linked","description":"x"}"#, None);
        std::os::unix::fs::symlink(tmp.path().join("hello/run.lua"), tmp.path().join("linked/run.lua")).unwrap();
        write_command(tmp.path(), "libfile", r#"{"name":"libfile","description":"x"}"#, Some("return function() end"));
        fs::write(tmp.path().join("libfile/lib"), "").unwrap();

        let registry = load(tmp.path()).unwrap();
        assert_eq!(registry.commands.len(), 1);
        assert!(registry.find("hello").is_some());
        assert!(registry.find("noscript").is_none());

        let broken: Vec<&str> = registry.problems.iter().map(|p| p.command.as_str()).collect();
        assert_eq!(broken, vec!["badjson", "group", "libfile", "linked", "noscript"]);
        assert_eq!(registry.problems[1].problem, "missing b.lua");
        assert_eq!(registry.problems[2].problem, "lib must be a folder, not a link or a file");
        assert_eq!(registry.problems[3].problem, "run.lua must be a plain file, not a link");
    }
}
