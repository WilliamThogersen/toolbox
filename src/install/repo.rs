//! Finds the commands in a fetched repo: one at the repo root, or one per top-level folder.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};

use crate::manifest::{Manifest, is_valid_name};
use crate::registry::{self, CommandDef, MANIFEST_FILE, Problem, SCRIPT_FILE};
use crate::runtime;
use crate::screen::one_line;

const ROOT_LABEL: &str = "(repo root)";

/// What a repo holds: the commands that passed every check, and the problems of the rest.
#[derive(Debug, Default)]
pub struct Scan {
    pub commands: Vec<CommandDef>,
    pub broken: Vec<Problem>,
}

impl Scan {
    pub fn find(&self, name: &str) -> Option<&CommandDef> {
        self.commands.iter().find(|def| def.manifest.name == name)
    }

    /// Every problem of the broken command `name`, joined; `None` when it isn't broken.
    pub fn problem_of(&self, name: &str) -> Option<String> {
        let problems: Vec<&str> = self
            .broken
            .iter()
            .filter(|p| p.command == name)
            .map(|p| p.problem.as_str())
            .collect();
        (!problems.is_empty()).then(|| problems.join("; "))
    }

    fn all_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self
            .commands
            .iter()
            .map(|def| def.manifest.name.as_str())
            .chain(self.broken.iter().map(|p| p.command.as_str()))
            .collect();
        names.sort();
        names.dedup();
        names
    }
}

/// Checks every command in `checkout`. Fails only when there are none at all.
pub fn scan(checkout: &Path) -> Result<Scan> {
    let found: Vec<std::result::Result<CommandDef, Vec<Problem>>> =
        if checkout.join(MANIFEST_FILE).symlink_metadata().is_ok() {
            vec![load_checked(checkout, None)]
        } else {
            command_folders(checkout)?
                .iter()
                .map(|(dir, folder)| load_checked(dir, Some(folder)))
                .collect()
        };
    ensure!(
        !found.is_empty(),
        "no commands found: put {MANIFEST_FILE} and {SCRIPT_FILE} at the repo root, or in one folder per command"
    );
    Ok(found.into_iter().fold(Scan::default(), |mut scan, result| {
        match result {
            Ok(def) => scan.commands.push(def),
            Err(problems) => scan.broken.extend(problems),
        }
        scan
    }))
}

/// What to install: the commands in `names`, or every valid one (skipping the broken) when empty.
#[derive(Debug)]
pub struct Selection {
    pub chosen: Vec<CommandDef>,
    pub skipped: Vec<Problem>,
}

/// A named command must exist and be valid. Broken commands nobody asked for never block.
pub fn select(scan: Scan, names: &[String]) -> Result<Selection> {
    if names.is_empty() {
        if scan.commands.is_empty() {
            bail!("every command in the repo is broken:\n{}", problem_lines(&scan.broken));
        }
        return Ok(Selection {
            chosen: scan.commands,
            skipped: scan.broken,
        });
    }
    let errors: Vec<String> = names
        .iter()
        .filter(|name| scan.find(name).is_none())
        .map(|name| match scan.problem_of(name) {
            Some(problem) => format!("  {name}: {problem}"),
            None if is_valid_name(name) => format!("  {name}: not in the repo (it has: {})", scan.all_names().join(", ")),
            None => format!("  {name:?}: not a valid command name"),
        })
        .collect();
    if !errors.is_empty() {
        bail!("nothing was installed:\n{}", errors.join("\n"));
    }
    let chosen = scan
        .commands
        .into_iter()
        .filter(|def| names.contains(&def.manifest.name))
        .collect();
    Ok(Selection {
        chosen,
        skipped: Vec::new(),
    })
}

pub fn problem_lines(problems: &[Problem]) -> String {
    problems
        .iter()
        .map(|p| format!("  {}: {}", one_line(&p.command), one_line(&p.problem)))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Top-level folders holding a `command.json`. Hidden folders and symlinks are skipped.
fn command_folders(checkout: &Path) -> Result<Vec<(PathBuf, String)>> {
    let mut folders: Vec<(PathBuf, String)> = fs::read_dir(checkout)
        .with_context(|| format!("could not read {}", checkout.display()))?
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|entry| {
            let folder = entry.file_name().to_str()?.to_string();
            (!folder.starts_with('.')).then(|| (entry.path(), folder))
        })
        .filter(|(dir, _)| dir.join(MANIFEST_FILE).symlink_metadata().is_ok())
        .collect();
    folders.sort();
    Ok(folders)
}

/// `folder` is `None` for a command at the repo root, which takes its name from the manifest.
fn load_checked(dir: &Path, folder: Option<&str>) -> std::result::Result<CommandDef, Vec<Problem>> {
    let label = folder.unwrap_or(ROOT_LABEL);
    let problem = |message: String| Problem {
        command: label.to_string(),
        problem: message,
    };
    // A symlink could point at any file on the installing machine. Check before reading.
    let not_regular: Vec<Problem> = [MANIFEST_FILE, SCRIPT_FILE]
        .into_iter()
        .filter(|file| dir.join(file).symlink_metadata().is_ok_and(|m| !m.is_file()))
        .map(|file| problem(format!("{file} must be a regular file, not a symlink or folder")))
        .collect();
    if !not_regular.is_empty() {
        return Err(not_regular);
    }
    let name = match folder {
        Some(folder) => folder.to_string(),
        None => root_name(dir).unwrap_or_else(|| ROOT_LABEL.to_string()),
    };
    let def = registry::load_command(dir, &name)?;
    let script = folder.map_or(SCRIPT_FILE.to_string(), |f| format!("{f}/{SCRIPT_FILE}"));
    runtime::check_syntax_as(&def, &script).map_err(|err| vec![problem(format!("{err:#}"))])?;
    Ok(def)
}

fn root_name(dir: &Path) -> Option<String> {
    let raw = fs::read_to_string(dir.join(MANIFEST_FILE)).ok()?;
    Manifest::parse(&raw).ok().map(|m| m.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_command(dir: &Path, name: &str, script: &str) {
        fs::create_dir_all(dir).unwrap();
        let manifest = format!(r#"{{"name":"{name}","version":"1.0.0","description":"x"}}"#);
        fs::write(dir.join(MANIFEST_FILE), manifest).unwrap();
        fs::write(dir.join(SCRIPT_FILE), script).unwrap();
    }

    fn names(defs: &[CommandDef]) -> Vec<&str> {
        defs.iter().map(|d| d.manifest.name.as_str()).collect()
    }

    fn picked(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    const OK: &str = "return function() end";

    #[test]
    fn root_command_wins_over_folders() {
        let tmp = tempfile::tempdir().unwrap();
        write_command(tmp.path(), "solo", OK);
        write_command(&tmp.path().join("other"), "other", OK);
        assert_eq!(names(&scan(tmp.path()).unwrap().commands), vec!["solo"]);
    }

    #[test]
    fn one_command_per_folder_skipping_hidden_and_plain_folders() {
        let tmp = tempfile::tempdir().unwrap();
        write_command(&tmp.path().join("b-cmd"), "b-cmd", OK);
        write_command(&tmp.path().join("a-cmd"), "a-cmd", OK);
        write_command(&tmp.path().join(".github"), "github", OK);
        fs::create_dir_all(tmp.path().join("docs")).unwrap();
        assert_eq!(names(&scan(tmp.path()).unwrap().commands), vec!["a-cmd", "b-cmd"]);
    }

    #[test]
    fn empty_repo_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let err = scan(tmp.path()).unwrap_err().to_string();
        assert!(err.contains("no commands found"), "{err}");
    }

    #[test]
    fn broken_commands_are_kept_apart_from_good_ones() {
        let tmp = tempfile::tempdir().unwrap();
        write_command(&tmp.path().join("good"), "good", OK);
        write_command(&tmp.path().join("syntax"), "syntax", "return function( end");
        write_command(&tmp.path().join("misnamed"), "other-name", OK);
        let found = scan(tmp.path()).unwrap();
        assert_eq!(names(&found.commands), vec!["good"]);
        assert!(found.problem_of("syntax").unwrap().contains("syntax/run.lua:1:"));
        assert!(found.problem_of("misnamed").unwrap().contains("folder name"));
        assert_eq!(found.problem_of("good"), None);
    }

    #[test]
    fn selecting_everything_skips_the_broken() {
        let tmp = tempfile::tempdir().unwrap();
        write_command(&tmp.path().join("good"), "good", OK);
        write_command(&tmp.path().join("bad"), "bad", "return function( end");
        let selection = select(scan(tmp.path()).unwrap(), &[]).unwrap();
        assert_eq!(names(&selection.chosen), vec!["good"]);
        assert_eq!(selection.skipped[0].command, "bad");

        fs::remove_dir_all(tmp.path().join("good")).unwrap();
        let err = select(scan(tmp.path()).unwrap(), &[]).unwrap_err().to_string();
        assert!(err.contains("every command in the repo is broken"), "{err}");
    }

    #[test]
    fn selecting_by_name_needs_each_to_exist_and_work() {
        let tmp = tempfile::tempdir().unwrap();
        write_command(&tmp.path().join("one"), "one", OK);
        write_command(&tmp.path().join("two"), "two", OK);
        write_command(&tmp.path().join("bad"), "bad", "return function( end");

        let selection = select(scan(tmp.path()).unwrap(), &picked(&["two"])).unwrap();
        assert_eq!(names(&selection.chosen), vec!["two"]);
        assert!(selection.skipped.is_empty(), "broken commands nobody picked are not reported");

        let err = select(scan(tmp.path()).unwrap(), &picked(&["one", "bad", "nope"])).unwrap_err().to_string();
        assert!(err.contains("bad: "), "{err}");
        assert!(err.contains("nope: not in the repo (it has: bad, one, two)"), "{err}");
        assert!(!err.contains("one:"), "{err}");
    }

    #[test]
    fn symlinked_files_are_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let secret = tmp.path().join("outside.txt");
        fs::write(&secret, "not lua").unwrap();
        let dir = tmp.path().join("repo").join("sneaky");
        write_command(&dir, "sneaky", OK);
        fs::remove_file(dir.join(SCRIPT_FILE)).unwrap();
        std::os::unix::fs::symlink(&secret, dir.join(SCRIPT_FILE)).unwrap();
        let found = scan(&tmp.path().join("repo")).unwrap();
        assert!(found.commands.is_empty());
        assert!(found.problem_of("sneaky").unwrap().contains("not a symlink"));
    }
}
