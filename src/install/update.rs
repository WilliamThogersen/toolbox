//! `tb self update`: fetch each installed command's repo again and take newer versions.
//!
//! With a `version` on both sides, only a higher version counts as newer, so authors can push
//! work in progress without shipping it. Without one, any new commit counts.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;

use super::confirm::{self, Confirm};
use super::source::{self, Source};
use super::repo::{self, Scan};
use super::{Staging, git, short};
use crate::manifest::{Manifest, Permissions};
use crate::registry::{CommandDef, MANIFEST_FILE, Problem};

#[derive(Debug, Default, Serialize)]
pub struct UpdateReport {
    pub updated: Vec<Change>,
    pub up_to_date: Vec<String>,
    pub problems: Vec<Problem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Change {
    pub name: String,
    /// Version, or short commit when the command has no version.
    pub from: String,
    pub to: String,
}

/// An installed command as it is on disk now.
struct Local {
    name: String,
    source: Source,
    manifest: Option<Manifest>,
}

struct Plan {
    def: CommandDef,
    source: Source,
    change: Change,
    old_permissions: Permissions,
}

enum Outcome {
    UpToDate(String),
    Update(Box<Plan>),
    Failed(Problem),
}

/// Updates every installed command, or only `only`.
pub fn update(commands_dir: &Path, only: Option<&str>, confirm: &dyn Confirm) -> Result<UpdateReport> {
    let locals: Vec<Local> = installed(commands_dir)?
        .into_iter()
        .filter(|local| only.is_none_or(|name| local.name == name))
        .collect();
    if let Some(name) = only {
        ensure!(
            !locals.is_empty(),
            "{name:?} is not an installed command. Only commands added with `tb self install` can be updated"
        );
    }
    let staging = Staging::new(commands_dir)?;
    let outcomes: Vec<Outcome> = by_repo(locals)
        .into_iter()
        .enumerate()
        .flat_map(|(i, group)| plan_repo(&staging.path().join(format!("checkout-{i}")), group))
        .collect();

    let plans: Vec<&Plan> = outcomes
        .iter()
        .filter_map(|o| match o {
            Outcome::Update(plan) => Some(plan.as_ref()),
            _ => None,
        })
        .collect();
    // New code from someone else's repo always needs a yes, even with the same permissions.
    if !plans.is_empty() {
        let question = match plans.len() {
            1 => "Update 1 command?".to_string(),
            n => format!("Update {n} commands?"),
        };
        if !confirm.confirm(&update_summary(&plans), &question)? {
            bail!("cancelled: nothing was updated");
        }
    }
    for plan in &plans {
        staging.put(commands_dir, &plan.def, &plan.source)?;
    }
    Ok(report(outcomes))
}

/// Sorted by name, so the order doesn't depend on which repo was fetched first.
fn report(outcomes: Vec<Outcome>) -> UpdateReport {
    let mut report = outcomes.into_iter().fold(UpdateReport::default(), |mut report, outcome| {
        match outcome {
            Outcome::UpToDate(name) => report.up_to_date.push(name),
            Outcome::Update(plan) => report.updated.push(plan.change),
            Outcome::Failed(problem) => report.problems.push(problem),
        }
        report
    });
    report.up_to_date.sort();
    report.updated.sort_by(|a, b| a.name.cmp(&b.name));
    report.problems.sort_by(|a, b| a.command.cmp(&b.command));
    report
}

/// Installed commands grouped by repo and ref, so each repo is fetched once.
fn by_repo(locals: Vec<Local>) -> Vec<Vec<Local>> {
    let mut groups: BTreeMap<(String, Option<String>), Vec<Local>> = BTreeMap::new();
    for local in locals {
        let key = (source::repo_key(&local.source.url).to_string(), local.source.git_ref.clone());
        groups.entry(key).or_default().push(local);
    }
    groups.into_values().collect()
}

fn plan_repo(checkout: &Path, group: Vec<Local>) -> Vec<Outcome> {
    let first = &group[0].source;
    let (url, git_ref) = (first.url.clone(), first.git_ref.clone());
    let fetched = git::fetch(&url, git_ref.as_deref(), checkout)
        .and_then(|commit| Ok((commit, repo::scan(checkout)?)));
    match fetched {
        Err(err) => group
            .into_iter()
            .map(|local| Outcome::Failed(Problem { command: local.name, problem: format!("{err:#}") }))
            .collect(),
        Ok((commit, scan)) => {
            let source = Source { url, git_ref, commit };
            group.into_iter().map(|local| plan_one(local, &source, &scan)).collect()
        }
    }
}

fn plan_one(local: Local, source: &Source, scan: &Scan) -> Outcome {
    let Some(def) = scan.find(&local.name) else {
        let problem = match scan.problem_of(&local.name) {
            Some(problem) => format!("broken in {}, so the installed copy stays: {problem}", source.url),
            None => format!("no longer in {}", source.url),
        };
        return Outcome::Failed(Problem {
            problem,
            command: local.name,
        });
    };
    if !is_newer(local.manifest.as_ref(), &local.source.commit, &def.manifest, &source.commit) {
        return Outcome::UpToDate(local.name);
    }
    let change = Change {
        name: local.name.clone(),
        from: version_or_commit(local.manifest.as_ref(), &local.source.commit),
        to: version_or_commit(Some(&def.manifest), &source.commit),
    };
    Outcome::Update(Box::new(Plan {
        def: def.clone(),
        source: source.clone(),
        change,
        old_permissions: local.manifest.map(|m| m.permissions).unwrap_or_default(),
    }))
}

fn is_newer(installed: Option<&Manifest>, installed_commit: &str, remote: &Manifest, remote_commit: &str) -> bool {
    match (installed.and_then(Manifest::semver), remote.semver()) {
        (Some(old), Some(new)) => new > old,
        _ => remote_commit != installed_commit,
    }
}

fn version_or_commit(manifest: Option<&Manifest>, commit: &str) -> String {
    manifest
        .and_then(|m| m.version.clone())
        .unwrap_or_else(|| short(commit).to_string())
}

/// Each update, where it comes from (to review the code), and what it may touch afterwards.
fn update_summary(plans: &[&Plan]) -> String {
    let lines: Vec<String> = plans
        .iter()
        .map(|plan| {
            let Change { name, from, to } = &plan.change;
            let new_perms = &plan.def.manifest.permissions;
            let perms = if plan.old_permissions == *new_perms {
                format!("    permissions: {}", confirm::permissions(new_perms))
            } else {
                format!(
                    "    permissions changed\n    before: {}\n    after:  {}",
                    confirm::permissions(&plan.old_permissions),
                    confirm::permissions(new_perms)
                )
            };
            format!(
                "  {name} {from} -> {to} from {}\n{perms}{}",
                plan.source.url,
                confirm::warning_lines(new_perms)
            )
        })
        .collect();
    format!("Updates:\n{}", lines.join("\n"))
}

/// Every command folder that has a `.source.json`, sorted by name.
fn installed(commands_dir: &Path) -> Result<Vec<Local>> {
    if !commands_dir.exists() {
        return Ok(Vec::new());
    }
    let mut dirs: Vec<PathBuf> = fs::read_dir(commands_dir)
        .with_context(|| format!("could not read {}", commands_dir.display()))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    dirs.iter()
        .filter_map(|dir| {
            let name = dir.file_name()?.to_str()?.to_string();
            source::read(dir).transpose().map(|source| {
                source.map(|source| Local {
                    name,
                    source,
                    manifest: read_manifest(dir),
                })
            })
        })
        .collect()
}

/// `None` when the local copy is broken: the update then replaces it.
fn read_manifest(dir: &Path) -> Option<Manifest> {
    Manifest::parse(&fs::read_to_string(dir.join(MANIFEST_FILE)).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(version: Option<&str>) -> Manifest {
        Manifest {
            name: "a".into(),
            version: version.map(str::to_string),
            description: "x".into(),
            args: BTreeMap::new(),
            permissions: Permissions::default(),
        }
    }

    #[test]
    fn versions_decide_when_both_sides_have_one() {
        let old = manifest(Some("1.2.0"));
        assert!(is_newer(Some(&old), "c1", &manifest(Some("1.10.0")), "c2"));
        assert!(!is_newer(Some(&old), "c1", &manifest(Some("1.2.0")), "c2"), "same version, new commit");
        assert!(!is_newer(Some(&old), "c1", &manifest(Some("1.1.9")), "c2"), "never downgrade");
    }

    #[test]
    fn commits_decide_without_versions() {
        assert!(is_newer(Some(&manifest(None)), "c1", &manifest(None), "c2"));
        assert!(!is_newer(Some(&manifest(None)), "c1", &manifest(None), "c1"));
        assert!(is_newer(Some(&manifest(Some("1.0.0"))), "c1", &manifest(None), "c2"));
        assert!(is_newer(None, "c1", &manifest(Some("1.0.0")), "c2"), "broken local copy");
    }

    #[test]
    fn changes_show_versions_or_short_commits() {
        assert_eq!(version_or_commit(Some(&manifest(Some("2.0.0"))), "abcdef1234"), "2.0.0");
        assert_eq!(version_or_commit(Some(&manifest(None)), "abcdef1234"), "abcdef1");
    }
}
