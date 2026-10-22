//! `tb self install|update|uninstall`: commands shared through git repos.
//!
//! An installed command is a normal command folder plus `.source.json`, which records the
//! repo it came from. Only `command.json` and `run.lua` are copied: scripts can't read
//! other files, so nothing else in the repo matters.

mod confirm;
mod git;
mod repo;
mod source;
mod update;

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use tempfile::TempDir;

use crate::manifest::{Permissions, is_valid_name};
use crate::registry::{CommandDef, MANIFEST_FILE, SCRIPT_FILE};

pub use confirm::{Confirm, Prompt, Yes};
pub use source::Source;
pub use update::update;

#[derive(Debug, Serialize)]
pub struct Installed {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub permissions: Permissions,
    pub dir: String,
    pub source: Source,
}

/// Installs every command in the repo, or none of them.
pub fn install(
    commands_dir: &Path,
    url: &str,
    git_ref: Option<&str>,
    confirm: &dyn Confirm,
) -> Result<Vec<Installed>> {
    let url = &git::resolve_url(url)?;
    let staging = Staging::new(commands_dir)?;
    let checkout = staging.path().join("checkout");
    let commit = git::fetch(url, git_ref, &checkout)?;
    let defs = repo::find_commands(&checkout)?;
    let conflicts: Vec<String> = defs
        .iter()
        .map(|def| conflict(commands_dir, url, &def.manifest.name))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();
    if !conflicts.is_empty() {
        bail!("nothing was installed:\n{}", conflicts.join("\n"));
    }

    let source = Source {
        url: url.to_string(),
        git_ref: git_ref.map(str::to_string),
        commit,
    };
    let question = match defs.len() {
        1 => "Install 1 command?".to_string(),
        n => format!("Install {n} commands?"),
    };
    if !confirm.confirm(&install_summary(&source, &defs), &question)? {
        bail!("cancelled: nothing was installed");
    }
    defs.iter()
        .map(|def| {
            let dir = staging.put(commands_dir, def, &source)?;
            Ok(Installed {
                name: def.manifest.name.clone(),
                version: def.manifest.version.clone(),
                permissions: def.manifest.permissions.clone(),
                dir: dir.display().to_string(),
                source: source.clone(),
            })
        })
        .collect()
}

/// Removes a command that `install` put there. Local commands are left alone.
pub fn uninstall(commands_dir: &Path, name: &str) -> Result<()> {
    ensure!(is_valid_name(name), "{name:?} is not a valid command name");
    let dir = commands_dir.join(name);
    ensure!(dir.is_dir(), "no command named {name:?}");
    ensure!(
        source::read(&dir)?.is_some(),
        "{name:?} was made locally, not installed, so uninstall leaves it alone. Delete {} yourself if you mean it",
        dir.display()
    );
    fs::remove_dir_all(&dir).with_context(|| format!("could not delete {}", dir.display()))
}

/// Reinstalling from the same repo replaces the old copy. Any other existing folder is a conflict.
fn conflict(commands_dir: &Path, url: &str, name: &str) -> Result<Option<String>> {
    let dir = commands_dir.join(name);
    if dir.symlink_metadata().is_err() {
        return Ok(None);
    }
    Ok(match source::read(&dir)? {
        Some(existing) if existing.same_repo(url) => None,
        Some(existing) => Some(format!(
            "  {name}: already installed from {}. Run `tb self uninstall {name}` first",
            existing.url
        )),
        None => Some(format!(
            "  {name}: a local command already has this name ({}). Rename or delete it first",
            dir.display()
        )),
    })
}

fn install_summary(source: &Source, defs: &[CommandDef]) -> String {
    let labels: Vec<String> = defs.iter().map(|def| confirm::label(&def.manifest)).collect();
    let width = labels.iter().map(String::len).max().unwrap_or(0);
    let lines: Vec<String> = defs
        .iter()
        .zip(&labels)
        .map(|(def, label)| {
            let perms = &def.manifest.permissions;
            format!("  {label:<width$}  {}{}", confirm::permissions(perms), confirm::warning_lines(perms))
        })
        .collect();
    format!("From {} at {}:\n{}", source.url, short(&source.commit), lines.join("\n"))
}

pub fn short(commit: &str) -> &str {
    &commit[..commit.len().min(7)]
}

/// Scratch space next to `commands/`, so moving a finished command into place is a rename.
struct Staging {
    dir: TempDir,
}

impl Staging {
    fn new(commands_dir: &Path) -> Result<Self> {
        fs::create_dir_all(commands_dir)
            .with_context(|| format!("could not create {}", commands_dir.display()))?;
        let parent = commands_dir.parent().context("the commands folder has no parent folder")?;
        let dir = tempfile::Builder::new()
            .prefix(".staging-")
            .tempdir_in(parent)
            .with_context(|| format!("could not create a staging folder in {}", parent.display()))?;
        Ok(Self { dir })
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Copies the command's two files plus `.source.json` into `commands_dir`, replacing an older copy.
    fn put(&self, commands_dir: &Path, def: &CommandDef, source: &Source) -> Result<PathBuf> {
        let name = &def.manifest.name;
        let staged = self.path().join("new").join(name);
        fs::create_dir_all(&staged)?;
        for file in [MANIFEST_FILE, SCRIPT_FILE] {
            fs::copy(def.dir.join(file), staged.join(file)).with_context(|| format!("could not copy {file}"))?;
        }
        source::write(&staged, source)?;

        let target = commands_dir.join(name);
        let old = self.path().join("old").join(name);
        let replacing = target.symlink_metadata().is_ok();
        if replacing {
            fs::create_dir_all(self.path().join("old"))?;
            fs::rename(&target, &old).with_context(|| format!("could not move the old {name} aside"))?;
        }
        if let Err(err) = fs::rename(&staged, &target) {
            let restore = if replacing { fs::rename(&old, &target).err() } else { None };
            let note = restore.map(|e| format!(" (the old copy could not be put back either: {e})"));
            return Err(err).with_context(|| {
                format!("could not move {name} into {}{}", commands_dir.display(), note.unwrap_or_default())
            });
        }
        Ok(target)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::process::Command;

    use super::*;

    /// Answers the prompt and remembers what it was shown.
    struct Answer {
        yes: bool,
        shown: RefCell<String>,
    }

    impl Confirm for Answer {
        fn confirm(&self, summary: &str, question: &str) -> Result<bool> {
            *self.shown.borrow_mut() = format!("{summary}\n{question}");
            Ok(self.yes)
        }
    }

    fn answer(yes: bool) -> Answer {
        Answer { yes, shown: RefCell::new(String::new()) }
    }

    fn repo_with(name: &str, manifest: &str) -> TempDir {
        let repo = tempfile::tempdir().unwrap();
        let dir = repo.path().join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(MANIFEST_FILE), manifest).unwrap();
        fs::write(dir.join(SCRIPT_FILE), "return function() end").unwrap();
        for args in [&["init", "--quiet"][..], &["add", "--all"], &["commit", "--quiet", "-m", "first"]] {
            let status = Command::new("git")
                .arg("-C")
                .arg(repo.path())
                .args(args)
                .envs([("GIT_CONFIG_GLOBAL", "/dev/null"), ("GIT_CONFIG_NOSYSTEM", "1")])
                .envs([("GIT_AUTHOR_NAME", "t"), ("GIT_AUTHOR_EMAIL", "t@t"), ("GIT_COMMITTER_NAME", "t"), ("GIT_COMMITTER_EMAIL", "t@t")])
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?}");
        }
        repo
    }

    #[test]
    fn the_human_sees_permissions_and_can_say_no() {
        let repo = repo_with("pr", r#"{"name":"pr","version":"1.0.0","description":"x","permissions":{"vault":["github"]}}"#);
        let url = repo.path().to_str().unwrap();
        let home = tempfile::tempdir().unwrap();
        let commands = home.path().join("commands");

        let no = answer(false);
        let err = install(&commands, url, None, &no).unwrap_err();
        assert!(err.to_string().contains("cancelled"), "{err}");
        assert!(!commands.join("pr").exists());
        let shown = no.shown.borrow();
        assert!(shown.contains("pr 1.0.0  vault: github"), "{shown}");
        assert!(shown.ends_with("Install 1 command?"), "{shown}");

        let installed = install(&commands, url, None, &answer(true)).unwrap();
        assert_eq!(installed[0].name, "pr");
        assert!(source::read(&commands.join("pr")).unwrap().is_some());
    }
}
