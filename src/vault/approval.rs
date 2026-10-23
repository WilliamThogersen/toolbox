//! Which commands may use a secret. A human allows each command at a terminal,
//! pinned to a fingerprint of its files, so any later edit (by hand, by an agent
//! or by `tb self update`) needs a new approval.

use std::collections::BTreeSet;

use anyhow::{Result, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::SecretEntry;
use crate::install::confirm;
use crate::manifest::Permissions;
use crate::registry::{CommandDef, Registry};

/// The command asking to use secrets, as it is about to run.
#[derive(Debug, Clone)]
pub struct Caller {
    pub name: String,
    /// The secrets its manifest lists in `permissions.vault`.
    pub declared: Vec<String>,
    pub fingerprint: String,
}

impl Caller {
    /// `script` must be the exact source that will run, so the approval covers what executes.
    pub fn new(def: &CommandDef, script: &str) -> Self {
        Self {
            name: def.manifest.name.clone(),
            declared: def.manifest.permissions.vault.clone(),
            fingerprint: fingerprint(&def.manifest_source, script),
        }
    }
}

/// SHA-256 over `command.json` and `run.lua`, each prefixed with its length so
/// bytes can't shift from one file to the other.
pub fn fingerprint(manifest: &str, script: &str) -> String {
    let mut hasher = Sha256::new();
    for part in [manifest, script] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    hasher.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Fails unless the human allowed exactly this version of the command to use `secret`.
pub fn check(secret: &str, entry: &SecretEntry, caller: &Caller) -> Result<()> {
    let name = &caller.name;
    match entry.commands.get(name) {
        Some(approved) if *approved == caller.fingerprint => Ok(()),
        Some(_) => bail!(
            "command {name:?} changed since the user allowed it to use secret {secret:?}. Ask the user to review it and run `tb self vault allow {secret} {name}` again in their own terminal"
        ),
        None => bail!(
            "command {name:?} is not allowed to use secret {secret:?} yet. Ask the user to run `tb self vault allow {secret} {name}` in their own terminal"
        ),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    /// Allowed, and unchanged since.
    Allowed,
    /// Allowed once, but its files changed since.
    Changed,
    /// Lists the secret in `permissions.vault`, but was never allowed.
    NotAllowed,
    /// Allowed once, but no longer installed (or broken).
    Missing,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CommandAccess {
    pub name: String,
    pub access: Access,
}

/// Every command that lists `secret` or was allowed to use it, sorted by name.
pub fn access(secret: &str, entry: &SecretEntry, registry: &Registry) -> Vec<CommandAccess> {
    let users = registry
        .commands
        .iter()
        .filter(|def| def.manifest.permissions.vault.iter().any(|s| s == secret))
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
        .and_then(|def| def.read_script().ok().map(|script| fingerprint(&def.manifest_source, &script)));
    match (entry.commands.get(name), current) {
        (None, _) => Access::NotAllowed,
        (Some(_), None) => Access::Missing,
        (Some(approved), Some(now)) if *approved == now => Access::Allowed,
        (Some(_), Some(_)) => Access::Changed,
    }
}

/// What the human sees before allowing a command to use a key.
pub struct Review {
    /// The short screen: the command, its permissions, where the key may go, and
    /// every line of the script that reaches outside it.
    pub summary: String,
    /// The whole script with line numbers, for the pager.
    pub full: String,
    pub question: String,
}

/// Globals a script reaches the world through. `_G`, `_ENV` and `rawget` reach the
/// same globals under another name, so lines using them are shown too.
const REACHING: &[&str] = &["http", "exec", "fs", "env", "stdin", "vault", "_G", "_ENV", "rawget"];

/// More than this and the short screen would be the long one again.
const MAX_SHOWN: usize = 25;

/// Built from the same text that gets fingerprinted, and escaped as a whole, since
/// any manifest string or script line could carry terminal codes.
pub fn review(def: &CommandDef, script: &str, secret: &str, entry: &SecretEntry) -> Review {
    let manifest = &def.manifest;
    let perms = one_line_permissions(&manifest.permissions);
    let query = if entry.query_params.is_empty() {
        String::new()
    } else {
        format!(" (also as query parameter {})", entry.query_params.join(", "))
    };
    let lines: Vec<&str> = script.lines().collect();
    let reaching: Vec<String> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| reaches_out(line))
        .map(|(i, line)| numbered(i + 1, line))
        .collect();
    let shown = match reaching.len() {
        0 => "  (none)".to_string(),
        n if n > MAX_SHOWN => format!("{}\n  ... and {} more", reaching[..MAX_SHOWN].join("\n"), n - MAX_SHOWN),
        _ => reaching.join("\n"),
    };
    let summary = format!(
        "{name} wants to use your key {secret}\n  {description}\n  permissions: {perms}{warnings}\n  \
         {secret} may be sent to {hosts}{query}\n\n\
         Lines of its run.lua ({count} in all) that reach outside the script:\n{shown}\n\n\
         Once allowed, this exact version can do anything the key allows on those hosts.",
        name = manifest.name,
        description = one_line(&manifest.description),
        perms = confirm::permissions(&perms),
        warnings = confirm::warning_lines(&perms),
        hosts = entry.hosts.join(", "),
        count = lines.len(),
    );
    let all: Vec<String> = lines.iter().enumerate().map(|(i, line)| numbered(i + 1, line)).collect();
    let full = format!("{}\n\n{}\n", def.script_path().display(), all.join("\n"));
    Review {
        summary: printable(&summary),
        full: printable(&full),
        question: printable(&format!("Allow {} to use {secret}?", manifest.name)),
    }
}

fn numbered(number: usize, line: &str) -> String {
    format!("{number:>5}  {}", line.trim_end())
}

/// A line that calls out of the sandbox, or names a URL.
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

/// Only the script may span lines. A newline in a manifest field could print a
/// fake line, like a second, harmless-looking `permissions:`.
fn one_line(text: &str) -> String {
    text.replace('\n', "\\n").replace('\t', "\\t")
}

fn one_line_permissions(perms: &Permissions) -> Permissions {
    let all = |values: &[String]| values.iter().map(|v| one_line(v)).collect();
    Permissions {
        http: all(&perms.http),
        vault: all(&perms.vault),
        exec: all(&perms.exec),
        env: all(&perms.env),
        read: all(&perms.read),
        write: all(&perms.write),
    }
}

/// Escapes characters that could hide or reorder text on a terminal: ANSI
/// escapes, carriage returns and bidi overrides ("Trojan Source").
fn printable(text: &str) -> String {
    text.chars()
        .map(|c| {
            let hidden = (c.is_control() && c != '\n' && c != '\t')
                || matches!(
                    c,
                    '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{2028}' | '\u{2029}'
                );
            if hidden { c.escape_unicode().to_string() } else { c.to_string() }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::manifest::Manifest;
    use crate::vault::SecretValue;

    fn entry(commands: &[(&str, &str)]) -> SecretEntry {
        SecretEntry {
            value: SecretValue::new("fake_token_abcdefgh".into()).unwrap(),
            hosts: vec!["api.github.com".into()],
            query_params: vec![],
            commands: commands.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
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
        Caller::new(def, &def.read_script().unwrap())
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
        assert!(err.contains("tb self vault allow github stars"), "{err}");

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
        let review = review(&def, script, "github", &entry(&[]));
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
        let review = review(&def, &script, "github", &entry(&[]));
        assert!(review.summary.contains("... and 3 more"), "{}", review.summary);
        assert_eq!(review.full.matches("http.get(1)").count(), MAX_SHOWN + 3);
    }
}
