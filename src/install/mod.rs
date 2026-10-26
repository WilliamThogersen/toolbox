pub mod confirm;
mod git;
pub mod market;
mod repo;
mod source;
mod update;

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use tempfile::TempDir;

use crate::command::manifest::{Permissions, is_valid_name};
use crate::command::registry::{CommandDef, MANIFEST_FILE, Problem, SCRIPT_FILE};
use crate::cli::screen::{one_line, one_line_permissions, printable};

pub use confirm::{Confirm, Prompt, Yes};
pub use source::Source;
pub use update::update;

#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    pub url: String,
    pub git_ref: Option<String>,
    pub names: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct InstallReport {
    pub installed: Vec<Installed>,
    pub skipped: Vec<Problem>,
}

#[derive(Debug, Serialize)]
pub struct Installed {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub permissions: Permissions,
    pub dir: String,
    pub source: Source,
}

#[derive(Debug, Clone, Serialize)]
pub struct Listing {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub market: Option<String>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub description: String,
    pub permissions: Permissions,
    pub installed: bool,
}

#[derive(Debug, Serialize)]
pub struct RepoListing {
    pub url: String,
    pub commit: String,
    pub commands: Vec<Listing>,
    pub broken: Vec<Problem>,
}

pub fn install(commands_dir: &Path, request: &Request, confirm: &dyn Confirm) -> Result<InstallReport> {
    let url = &git::resolve_url(&request.url)?;
    let staging = Staging::new(commands_dir)?;
    let (commit, scan) = staging.fetch(url, request.git_ref.as_deref())?;
    let selection = repo::select(scan, &request.names)?;
    let conflicts: Vec<String> = selection
        .chosen
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
        url: url.clone(),
        git_ref: request.git_ref.clone(),
        commit,
    };
    let question = match selection.chosen.len() {
        1 => "Install 1 command?".to_string(),
        n => format!("Install {n} commands?"),
    };
    if !confirm.confirm(&install_summary(&source, &selection), &question)? {
        bail!("cancelled: nothing was installed");
    }
    let installed = selection
        .chosen
        .iter()
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
        .collect::<Result<Vec<_>>>()?;
    Ok(InstallReport {
        installed,
        skipped: selection.skipped,
    })
}

pub fn list(commands_dir: &Path, url: &str, git_ref: Option<&str>) -> Result<RepoListing> {
    let url = git::resolve_url(url)?;
    let staging = Staging::new(commands_dir)?;
    let (commit, scan) = staging.fetch(&url, git_ref)?;
    let commands = scan
        .commands
        .iter()
        .map(|def| Listing {
            market: None,
            name: def.manifest.name.clone(),
            version: def.manifest.version.clone(),
            description: def.manifest.description.clone(),
            permissions: def.manifest.permissions.clone(),
            installed: installed_from(commands_dir, &def.manifest.name, &url),
        })
        .collect();
    Ok(RepoListing {
        url,
        commit,
        commands,
        broken: scan.broken,
    })
}

fn installed_from(commands_dir: &Path, name: &str, url: &str) -> bool {
    source::read(&commands_dir.join(name))
        .ok()
        .flatten()
        .is_some_and(|existing| existing.same_repo(url))
}

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

fn install_summary(source: &Source, selection: &repo::Selection) -> String {
    let defs = &selection.chosen;
    let labels: Vec<String> = defs.iter().map(|def| confirm::label(&def.manifest)).collect();
    let width = labels.iter().map(String::len).max().unwrap_or(0);
    let lines: Vec<String> = defs
        .iter()
        .zip(&labels)
        .map(|(def, label)| {
            let perms = one_line_permissions(&def.manifest.permissions);
            format!("  {label:<width$}  {}{}", confirm::permissions(&perms), confirm::warning_lines(&perms))
        })
        .collect();
    let skipped = if selection.skipped.is_empty() {
        String::new()
    } else {
        format!("\nSkipped, broken:\n{}", repo::problem_lines(&selection.skipped))
    };
    printable(&format!(
        "From {} at {}:\n{}{skipped}",
        one_line(&source.url),
        short(&source.commit),
        lines.join("\n")
    ))
}

pub fn short(commit: &str) -> &str {
    &commit[..commit.len().min(7)]
}

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

    fn fetch(&self, url: &str, git_ref: Option<&str>) -> Result<(String, repo::Scan)> {
        let checkout = self.path().join("checkout");
        let commit = git::fetch(url, git_ref, &checkout)?;
        Ok((commit, repo::scan(&checkout)?))
    }

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

    fn request(url: &str) -> Request {
        Request {
            url: url.to_string(),
            git_ref: None,
            names: Vec::new(),
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
        let err = install(&commands, &request(url), &no).unwrap_err();
        assert!(err.to_string().contains("cancelled"), "{err}");
        assert!(!commands.join("pr").exists());
        let shown = no.shown.borrow();
        assert!(shown.contains("pr 1.0.0  vault: github"), "{shown}");
        assert!(shown.ends_with("Install 1 command?"), "{shown}");

        let report = install(&commands, &request(url), &answer(true)).unwrap();
        assert_eq!(report.installed[0].name, "pr");
        assert!(source::read(&commands.join("pr")).unwrap().is_some());
    }

    #[test]
    fn manifest_text_cannot_rewrite_the_prompt() {
        let manifest = r#"{"name":"pr","description":"x","permissions":{"exec":["git"],"http":["a.com\u001b[1A\u001b[2K\n  pr  no permissions"]}}"#;
        let repo = repo_with("pr", manifest);
        let home = tempfile::tempdir().unwrap();
        let no = answer(false);
        install(&home.path().join("commands"), &request(repo.path().to_str().unwrap()), &no).unwrap_err();
        let shown = no.shown.borrow();
        assert!(!shown.contains('\u{1b}'), "{shown}");
        assert!(!shown.contains("\n  pr  no permissions"), "{shown}");
        assert!(shown.contains("exec runs git"), "{shown}");
    }
}
