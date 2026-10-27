use std::collections::BTreeSet;

use anyhow::{Result, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::commands::destination;
use super::{SecretEntry, names};
use crate::install::confirm;
use crate::command::entry::Entry;
use crate::command::registry::{CommandDef, Registry};
use crate::command::sources::Sources;
use crate::cli::screen::{one_line, one_line_permissions, printable};

#[derive(Debug, Clone)]
pub struct Caller {
    pub name: String,
    pub declared: Vec<String>,
    pub fingerprint: String,
}

impl Caller {
    pub fn new(def: &CommandDef, entry: &Entry, sources: &Sources) -> Self {
        Self {
            name: def.manifest.name.clone(),
            declared: entry.permissions.vault.clone(),
            fingerprint: sources.fingerprint(&def.manifest_source),
        }
    }
}

pub fn fingerprint(manifest: &str, script: &str) -> String {
    hash_parts(b"", [manifest, script])
}

const FILES_TAG: &[u8] = b"toolbox files v1\n";

pub fn files_fingerprint<'a>(manifest: &'a str, files: impl Iterator<Item = (&'a str, &'a str)>) -> String {
    let parts = std::iter::once(manifest).chain(files.flat_map(|(path, text)| [path, text]));
    hash_parts(FILES_TAG, parts)
}

fn hash_parts<'a>(tag: &[u8], parts: impl IntoIterator<Item = &'a str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(tag);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    hasher.finalize().iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().concat()
}

pub fn check(secret: &str, entry: &SecretEntry, caller: &Caller) -> Result<()> {
    let name = &caller.name;
    match entry.commands.get(name) {
        Some(approved) if *approved == caller.fingerprint => Ok(()),
        Some(_) => bail!(
            "command {name:?} changed since the user allowed it to use secret {secret:?}. Ask the user to review it with `tb self vault setup {name}` in their own terminal"
        ),
        None => bail!(
            "command {name:?} is not allowed to use secret {secret:?} yet. Ask the user to run `tb self vault setup {name}` in their own terminal"
        ),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    Allowed,
    Changed,
    NotAllowed,
    Missing,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CommandAccess {
    pub name: String,
    pub access: Access,
}

pub fn access(secret: &str, entry: &SecretEntry, registry: &Registry) -> Vec<CommandAccess> {
    let users = registry
        .commands
        .iter()
        .filter(|def| names::declared(&def.manifest.all_permissions().vault, secret))
        .map(|def| def.manifest.name.as_str());
    let names: BTreeSet<&str> = users.chain(entry.commands.keys().map(String::as_str)).collect();
    names
        .into_iter()
        .map(|name| CommandAccess {
            name: name.to_string(),
            access: access_of(name, entry, registry),
        })
        .collect()
}

fn access_of(name: &str, entry: &SecretEntry, registry: &Registry) -> Access {
    let current = registry
        .find(name)
        .and_then(|def| Sources::read(def).ok().map(|sources| sources.fingerprint(&def.manifest_source)));
    match (entry.commands.get(name), current) {
        (None, _) => Access::NotAllowed,
        (Some(_), None) => Access::Missing,
        (Some(approved), Some(now)) if *approved == now => Access::Allowed,
        (Some(_), Some(_)) => Access::Changed,
    }
}

pub struct Review {
    pub summary: String,
    pub full: String,
    pub question: String,
}

const REACHING: &[&str] = &["http", "exec", "fs", "env", "stdin", "prompt", "vault", "_G", "_ENV", "rawget"];

const MAX_SHOWN: usize = 25;

pub fn review(def: &CommandDef, sources: &Sources, keys: &[(&str, &SecretEntry)]) -> Review {
    debug_assert!(!keys.is_empty(), "a review asks about at least one key");
    let manifest = &def.manifest;
    let perms = one_line_permissions(&manifest.all_permissions());
    let names: Vec<&str> = keys.iter().map(|(name, _)| *name).collect();
    let (wants, what) = match names.as_slice() {
        [one] => (format!("your key {one}"), "the key allows"),
        many => (format!("your keys {}", many.join(", ")), "these keys allow"),
    };
    let destinations: Vec<String> = keys
        .iter()
        .map(|(name, entry)| format!("  {name} may be sent to {}", destination(entry)))
        .collect();
    let (files, outside) = match sources.paths().as_slice() {
        [only] => (format!("its {only}"), "the script"),
        many => (format!("its {} Lua files", many.len()), "the scripts"),
    };
    let summary = format!(
        "{name} wants to use {wants}\n  {description}\n  permissions: {perms}{warnings}\n{destinations}\n\n\
         Lines of {files} ({count} in all) that reach outside {outside}:\n{shown}\n\n\
         Once allowed, this exact version can do anything {what} on those hosts.",
        name = manifest.name,
        description = one_line(&manifest.description),
        perms = confirm::permissions(&perms),
        warnings = confirm::warning_lines(&perms),
        destinations = destinations.join("\n"),
        count = sources.files().map(|(_, text)| text.lines().count()).sum::<usize>(),
        shown = shown(&reaching_lines(sources)),
    );
    Review {
        summary: printable(&summary),
        full: printable(&full_text(def, sources)),
        question: printable(&format!("Allow {} to use {}?", manifest.name, names.first().copied().unwrap_or_default())),
    }
}

fn reaching_lines(sources: &Sources) -> Vec<String> {
    let many = sources.paths().len() > 1;
    sources
        .files()
        .flat_map(|(path, text)| {
            text.lines()
                .enumerate()
                .filter(|(_, line)| reaches_out(line))
                .map(move |(i, line)| {
                    if many {
                        format!("  {path}:{}  {}", i + 1, line.trim_end())
                    } else {
                        numbered(i + 1, line)
                    }
                })
        })
        .collect()
}

fn shown(reaching: &[String]) -> String {
    match reaching.len() {
        0 => "  (none)".to_string(),
        n if n > MAX_SHOWN => {
            let first: Vec<&str> = reaching.iter().take(MAX_SHOWN).map(String::as_str).collect();
            format!("{}\n  ... and {} more", first.join("\n"), n - MAX_SHOWN)
        }
        _ => reaching.join("\n"),
    }
}

fn full_text(def: &CommandDef, sources: &Sources) -> String {
    let files: Vec<String> = sources
        .files()
        .map(|(path, text)| {
            let all: Vec<String> = text.lines().enumerate().map(|(i, line)| numbered(i + 1, line)).collect();
            format!("{}\n\n{}\n", def.dir.join(path).display(), all.join("\n"))
        })
        .collect();
    files.join("\n")
}

fn numbered(number: usize, line: &str) -> String {
    format!("{number:>5}  {}", line.trim_end())
}

fn reaches_out(line: &str) -> bool {
    line.contains("://") || REACHING.iter().any(|word| has_word(line, word))
}

fn has_word(line: &str, word: &str) -> bool {
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    line.match_indices(word).any(|(at, _)| {
        let before = line[..at].chars().next_back();
        let after = line[at + word.len()..].chars().next();
        !before.is_some_and(ident) && !after.is_some_and(ident)
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::command::manifest::Manifest;
    use crate::vault::SecretValue;

    fn entry(commands: &[(&str, &str)]) -> SecretEntry {
        SecretEntry {
            commands: commands.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            ..SecretEntry::new(SecretValue::new("fake_token_abcdefgh".into()).unwrap(), vec!["api.github.com".into()])
        }
    }

    fn command(root: &std::path::Path, name: &str, vault: &[&str], script: &str) -> CommandDef {
        let dir = root.join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("run.lua"), script).unwrap();
        let source = serde_json::json!({
            "name": name,
            "description": "test\n  permissions: no permissions",
            "permissions": { "http": ["api.github.com"], "vault": vault, "read": ["/tmp/\u{1b}[8m", "/a\nfake"] },
        })
        .to_string();
        CommandDef {
            manifest: Manifest::parse(&source).unwrap(),
            manifest_source: source,
            dir,
        }
    }

    fn caller(def: &CommandDef) -> Caller {
        let sources = Sources::read(def).unwrap();
        Caller::new(def, &def.manifest.entry(None).unwrap(), &sources)
    }

    #[test]
    fn fingerprint_covers_both_files_and_their_boundary() {
        let base = fingerprint("{}", "return 1");
        assert_eq!(base.len(), 64);
        assert_eq!(base, fingerprint("{}", "return 1"));
        assert_ne!(base, fingerprint("{ }", "return 1"));
        assert_ne!(base, fingerprint("{}", "return 2"));
        assert_ne!(fingerprint("ab", "c"), fingerprint("a", "bc"));
    }

    #[test]
    fn check_needs_an_approval_for_this_exact_version() {
        let tmp = tempfile::tempdir().unwrap();
        let def = command(tmp.path(), "stars", &["github"], "return function() end");
        let who = caller(&def);

        let err = check("github", &entry(&[]), &who).unwrap_err().to_string();
        assert!(err.contains("tb self vault setup stars"), "{err}");

        assert!(check("github", &entry(&[("stars", &who.fingerprint)]), &who).is_ok());

        let err = check("github", &entry(&[("stars", "old")]), &who).unwrap_err().to_string();
        assert!(err.contains("changed since"), "{err}");
    }

    #[test]
    fn access_reports_every_state() {
        let tmp = tempfile::tempdir().unwrap();
        let allowed = command(tmp.path(), "allowed", &["github"], "return function() end");
        let changed = command(tmp.path(), "changed", &["github"], "return function() end");
        let never = command(tmp.path(), "never", &["github"], "return function() end");
        let other = command(tmp.path(), "other", &["stripe"], "return function() end");
        let grants = [
            ("allowed", caller(&allowed).fingerprint),
            ("changed", "old".to_string()),
            ("gone", "old".to_string()),
        ];
        let entry = entry(&grants.iter().map(|(k, v)| (*k, v.as_str())).collect::<Vec<_>>());
        let registry = Registry {
            commands: vec![allowed, changed, never, other],
            problems: vec![],
        };
        let states: Vec<(String, Access)> = access("github", &entry, &registry)
            .into_iter()
            .map(|a| (a.name, a.access))
            .collect();
        assert_eq!(
            states,
            vec![
                ("allowed".into(), Access::Allowed),
                ("changed".into(), Access::Changed),
                ("gone".into(), Access::Missing),
                ("never".into(), Access::NotAllowed),
            ]
        );
    }

    #[test]
    fn review_shows_lines_that_reach_out_and_escapes_hidden_characters() {
        let tmp = tempfile::tempdir().unwrap();
        let script = "local API = \"https://api.github.com\"\nlocal n = 1\nreturn function()\n  \
                      local res = http.get(API) -- \u{1b}[2Khidden\u{202e}x\rcover\n  local httpish = 2\nend\n";
        let def = command(tmp.path(), "stars", &["github"], script);
        let review = review(&def, &Sources::read(&def).unwrap(), &[("github", &entry(&[]))]);
        let summary = &review.summary;
        assert!(summary.starts_with("stars wants to use your key github\n"), "{summary}");
        assert!(summary.contains("    1  local API = \"https://api.github.com\""), "{summary}");
        assert!(summary.contains("    4    local res = http.get(API) -- \\u{1b}[2Khidden\\u{202e}x\\u{d}cover"), "{summary}");
        assert!(!summary.contains("local n = 1") && !summary.contains("httpish"), "{summary}");
        assert!(summary.contains("(6 in all)"), "{summary}");
        assert!(summary.contains("read: /tmp/\\u{1b}[8m, /a\\nfake"), "{summary}");
        assert!(summary.contains("  test\\n  permissions: no permissions\n"), "{summary}");
        assert_eq!(summary.matches("\n  permissions:").count(), 1, "{summary}");
        assert!(summary.contains("github may be sent to api.github.com"), "{summary}");
        for text in [summary, &review.full, &review.question] {
            assert!(!text.contains('\u{1b}') && !text.contains('\u{202e}') && !text.contains('\r'));
        }
        assert!(review.full.contains("    2  local n = 1\n"), "{}", review.full);
        assert!(review.full.contains("    5    local httpish = 2\n"), "{}", review.full);
        assert_eq!(review.question, "Allow stars to use github?");
    }

    #[test]
    fn review_lists_where_each_key_may_go() {
        let tmp = tempfile::tempdir().unwrap();
        let def = command(tmp.path(), "both", &["github/*"], "return function() end");
        let maps = SecretEntry { query_params: vec!["key".into()], ..entry(&[]) };
        let review = review(&def, &Sources::read(&def).unwrap(), &[("github/work", &entry(&[])), ("github/maps", &maps)]);
        let summary = &review.summary;
        assert!(summary.starts_with("both wants to use your keys github/work, github/maps\n"), "{summary}");
        assert!(summary.contains("  github/work may be sent to api.github.com\n"), "{summary}");
        assert!(summary.contains("  github/maps may be sent to api.github.com (also as query parameter key)\n"), "{summary}");
        assert!(summary.contains("anything these keys allow"), "{summary}");
        assert_eq!(review.question, "Allow both to use github/work?");
    }

    #[test]
    fn review_covers_every_lua_file_of_a_group() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("notes");
        fs::create_dir_all(dir.join("lib")).unwrap();
        fs::write(dir.join("add.lua"), "local api = require('api')\nreturn function() return api.post() end").unwrap();
        fs::write(dir.join("lib/api.lua"), "local api = {}\nfunction api.post()\n  return http.post('https://api.github.com/x')\nend\nreturn api").unwrap();
        let source = serde_json::json!({
            "name": "notes",
            "description": "Keeps notes",
            "subcommands": { "add": { "description": "x", "permissions": { "http": ["api.github.com"], "vault": ["github"] } } },
        })
        .to_string();
        let def = CommandDef { manifest: Manifest::parse(&source).unwrap(), manifest_source: source, dir: dir.clone() };
        let review = review(&def, &Sources::read(&def).unwrap(), &[("github", &entry(&[]))]);
        let summary = &review.summary;
        assert!(summary.contains("permissions: http: api.github.com; vault: github"), "{summary}");
        assert!(summary.contains("Lines of its 2 Lua files (7 in all) that reach outside the scripts:\n  lib/api.lua:3    return http.post('https://api.github.com/x')\n"), "{summary}");
        assert!(!summary.contains("add.lua:"), "{summary}");
        assert!(review.full.contains(&format!("{}\n\n    1  local api = require('api')\n", dir.join("add.lua").display())), "{}", review.full);
        assert!(review.full.contains(&format!("{}\n\n    1  local api = {{}}\n", dir.join("lib/api.lua").display())), "{}", review.full);
    }

    #[test]
    fn reaching_out_means_whole_words() {
        for line in ["http.get(x)", "local f = fs", "exec(\"git\")", "x = _G[\"ht\" .. \"tp\"]", "rawget(_ENV, k)", "u = 'http://x'", "vault('k')"] {
            assert!(reaches_out(line), "{line}");
        }
        for line in ["local https = 1", "local myfs = 2", "envelope()", "-- nothing here", "vaulted = true"] {
            assert!(!reaches_out(line), "{line}");
        }
    }

    #[test]
    fn a_long_list_is_cut_short() {
        let tmp = tempfile::tempdir().unwrap();
        let script = "http.get(1)\n".repeat(MAX_SHOWN + 3);
        let def = command(tmp.path(), "many", &["github"], &script);
        let review = review(&def, &Sources::read(&def).unwrap(), &[("github", &entry(&[]))]);
        assert!(review.summary.contains("... and 3 more"), "{}", review.summary);
        assert_eq!(review.full.matches("http.get(1)").count(), MAX_SHOWN + 3);
    }
}
