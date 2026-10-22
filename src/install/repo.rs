//! Finds the commands in a fetched repo: one at the repo root, or one per top-level folder.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};

use crate::manifest::Manifest;
use crate::registry::{self, CommandDef, MANIFEST_FILE, Problem, SCRIPT_FILE};
use crate::runtime;

const ROOT_LABEL: &str = "(repo root)";

/// Every command in `checkout`, all valid, or an error listing every problem.
pub fn find_commands(checkout: &Path) -> Result<Vec<CommandDef>> {
    let found: Vec<std::result::Result<CommandDef, Vec<Problem>>> = if checkout.join(MANIFEST_FILE).symlink_metadata().is_ok() {
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
    let problems: Vec<String> = found
        .iter()
        .filter_map(|r| r.as_ref().err())
        .flatten()
        .map(|p| format!("  {}: {}", p.command, p.problem))
        .collect();
    if !problems.is_empty() {
        bail!("the repo has broken commands, so nothing changed:\n{}", problems.join("\n"));
    }
    Ok(found.into_iter().filter_map(Result::ok).collect())
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
    runtime::check_syntax(&def).map_err(|err| vec![problem(format!("{err:#}"))])?;
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

    const OK: &str = "return function() end";

    #[test]
    fn root_command_wins_over_folders() {
        let tmp = tempfile::tempdir().unwrap();
        write_command(tmp.path(), "solo", OK);
        write_command(&tmp.path().join("other"), "other", OK);
        assert_eq!(names(&find_commands(tmp.path()).unwrap()), vec!["solo"]);
    }

    #[test]
    fn one_command_per_folder_skipping_hidden_and_plain_folders() {
        let tmp = tempfile::tempdir().unwrap();
        write_command(&tmp.path().join("b-cmd"), "b-cmd", OK);
        write_command(&tmp.path().join("a-cmd"), "a-cmd", OK);
        write_command(&tmp.path().join(".github"), "github", OK);
        fs::create_dir_all(tmp.path().join("docs")).unwrap();
        assert_eq!(names(&find_commands(tmp.path()).unwrap()), vec!["a-cmd", "b-cmd"]);
    }

    #[test]
    fn empty_repo_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let err = find_commands(tmp.path()).unwrap_err().to_string();
        assert!(err.contains("no commands found"), "{err}");
    }

    #[test]
    fn any_broken_command_fails_the_whole_repo() {
        let tmp = tempfile::tempdir().unwrap();
        write_command(&tmp.path().join("good"), "good", OK);
        write_command(&tmp.path().join("syntax"), "syntax", "return function( end");
        write_command(&tmp.path().join("misnamed"), "other-name", OK);
        let err = find_commands(tmp.path()).unwrap_err().to_string();
        assert!(err.contains("syntax:"), "{err}");
        assert!(err.contains("misnamed:"), "{err}");
        assert!(!err.contains("good:"), "{err}");
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
        let err = find_commands(&tmp.path().join("repo")).unwrap_err().to_string();
        assert!(err.contains("not a symlink"), "{err}");
    }
}
