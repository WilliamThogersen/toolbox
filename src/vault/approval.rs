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

/// What the human sees before allowing: the command, its permissions, its whole
/// script, and where the key may go. Built from the same text that gets fingerprinted,
/// and escaped as a whole, since any manifest string could carry terminal codes.
pub fn prompt(def: &CommandDef, script: &str, secret: &str, entry: &SecretEntry) -> String {
    let manifest = &def.manifest;
    let perms = one_line_permissions(&manifest.permissions);
    let rule = "-".repeat(72);
    let query = if entry.query_params.is_empty() {
        String::new()
    } else {
        format!(" (also as query parameter {})", entry.query_params.join(", "))
    };
    let text = format!(
        "Command {name}: {description}\n  permissions: {perms}{warnings}\n\n{path}\n{rule}\n{script}\n{rule}\n\
         {secret} may be sent to {hosts}{query}.\n\
         Once allowed, this command can do anything the key allows there. Read the script above first.\n\
         Allow {name} to use {secret}?",
        name = manifest.name,
        description = one_line(&manifest.description),
        perms = confirm::permissions(&perms),
        warnings = confirm::warning_lines(&perms),
        path = def.script_path().display(),
        script = script.trim_end(),
        hosts = entry.hosts.join(", "),
    );
    printable(&text)
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
    fn prompt_shows_the_script_with_hidden_characters_escaped() {
        let tmp = tempfile::tempdir().unwrap();
        let script = "return function()\n  -- \u{1b}[2Khidden\u{202e}x\r\nend\n";
        let def = command(tmp.path(), "stars", &["github"], script);
        let text = prompt(&def, script, "github", &entry(&[]));
        assert!(text.contains("return function()"), "{text}");
        assert!(text.contains("\\u{1b}[2Khidden\\u{202e}x\\u{d}"), "{text}");
        assert!(text.contains("read: /tmp/\\u{1b}[8m, /a\\nfake"), "{text}");
        assert!(text.contains("Command stars: test\\n  permissions: no permissions\n"), "{text}");
        assert_eq!(text.matches("\n  permissions:").count(), 1, "{text}");
        assert!(!text.contains('\u{1b}') && !text.contains('\u{202e}') && !text.contains('\r'));
        assert!(text.contains("vault: github"), "{text}");
        assert!(text.contains("may be sent to api.github.com"), "{text}");
        assert!(text.ends_with("Allow stars to use github?"), "{text}");
    }
}
