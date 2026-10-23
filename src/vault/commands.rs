//! `tb self vault add|list|allow|revoke|rm`. Every change needs a human at a terminal.

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use anyhow::{Result, anyhow, bail, ensure};

use super::hosts::{normalize_host, normalize_query_param};
use super::log::{AuditLog, Event};
use super::{SecretEntry, SecretSummary, SecretValue, VaultStore, approval};
use crate::manifest::is_valid_name;
use crate::registry::{CommandDef, Registry};

/// Human input. The real one reads `/dev/tty`, which scripts and agents can't type into.
pub trait Terminal {
    fn read_secret(&self, prompt: &str) -> Result<String>;
    fn confirm(&self, prompt: &str) -> Result<bool>;
    /// Shows `summary`, then asks `question`. Answering `v` shows `full` in a pager
    /// and asks again.
    fn review(&self, summary: &str, full: &str, question: &str) -> Result<bool>;
}

pub struct Tty;

impl Terminal for Tty {
    fn read_secret(&self, prompt: &str) -> Result<String> {
        rpassword::prompt_password(prompt).map_err(no_tty)
    }

    fn confirm(&self, prompt: &str) -> Result<bool> {
        let tty = open_tty()?;
        Ok(matches!(ask(&tty, &format!("{prompt} [y/N] "))?.as_str(), "y" | "Y" | "yes"))
    }

    fn review(&self, summary: &str, full: &str, question: &str) -> Result<bool> {
        let mut tty = open_tty()?;
        writeln!(tty, "{summary}\n")?;
        loop {
            match ask(&tty, &format!("{question} [y/N, v = read the whole script] "))?.as_str() {
                "v" | "V" => page(&tty, full)?,
                "y" | "Y" | "yes" => return Ok(true),
                _ => return Ok(false),
            }
        }
    }
}

fn open_tty() -> Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(no_tty)
}

fn ask(mut tty: &File, prompt: &str) -> Result<String> {
    write!(tty, "{prompt}")?;
    tty.flush()?;
    let mut answer = String::new();
    BufReader::new(tty).read_line(&mut answer)?;
    Ok(answer.trim().to_string())
}

/// Shows `text` in `less` on the terminal, never on stdout, which carries the JSON
/// result. The system `less`, not whatever `less` is first in PATH. Without it, the
/// text is printed.
fn page(mut tty: &File, text: &str) -> Result<()> {
    let spawned = Command::new("/usr/bin/less")
        .stdin(Stdio::piped())
        .stdout(tty.try_clone()?)
        .spawn();
    let Ok(mut less) = spawned else {
        tty.write_all(text.as_bytes())?;
        return Ok(());
    };
    if let Some(mut input) = less.stdin.take() {
        // Quitting before the end closes the pipe, which is fine.
        let _ = input.write_all(text.as_bytes());
    }
    less.wait()?;
    Ok(())
}

fn no_tty(err: io::Error) -> anyhow::Error {
    anyhow!(
        "this needs a human at an interactive terminal ({err}). Ask the user to run the command themselves in a terminal window"
    )
}

/// Where a secret may go, as given on the command line.
pub struct Rules<'a> {
    pub hosts: &'a [String],
    pub query_params: &'a [String],
}

/// Adds a secret, or replaces its rules. For an existing secret an empty value
/// keeps the stored one, and the commands allowed to use it stay allowed.
pub fn add(
    store: &dyn VaultStore,
    log: &dyn AuditLog,
    term: &dyn Terminal,
    registry: &Registry,
    name: &str,
    rules: Rules,
) -> Result<SecretSummary> {
    ensure!(is_valid_name(name), "{name:?} is not a valid secret name (a-z, 0-9, '-', '_')");
    ensure!(!rules.hosts.is_empty(), "give at least one --host the secret may be sent to");
    let hosts: BTreeSet<String> = rules.hosts.iter().map(|h| normalize_host(h)).collect::<Result<_>>()?;
    let query_params: BTreeSet<String> = rules
        .query_params
        .iter()
        .map(|p| normalize_query_param(p))
        .collect::<Result<_>>()?;
    let vault = store.load()?;
    let existing = vault.get(name);
    let prompt = match existing {
        Some(_) => format!("New value for {name} (input is hidden, leave empty to keep the current one): "),
        None => format!("Value for {name} (input is hidden): "),
    };
    let typed = term.read_secret(&prompt)?;
    let new_value = !typed.trim().is_empty() || existing.is_none();
    let value = match (typed.trim(), existing) {
        ("", Some(current)) => current.value.clone(),
        (typed, _) => SecretValue::new(typed.to_string())?,
    };
    let entry = SecretEntry {
        value,
        hosts: hosts.into_iter().collect(),
        query_params: query_params.into_iter().collect(),
        commands: existing.map(|current| current.commands.clone()).unwrap_or_default(),
    };
    store.save(&vault.with_secret(name, entry.clone()))?;
    log.record(Event::Added {
        key: name.to_string(),
        hosts: entry.hosts.clone(),
        query_params: entry.query_params.clone(),
        new_value,
    });
    Ok(entry.summary(name, registry))
}

pub fn list(store: &dyn VaultStore, registry: &Registry) -> Result<Vec<SecretSummary>> {
    Ok(store.load()?.summaries(registry))
}

/// Lets one command use a secret, after showing the human exactly what it runs.
/// Returns whether access was given (the human may decline).
pub fn allow(
    store: &dyn VaultStore,
    log: &dyn AuditLog,
    term: &dyn Terminal,
    registry: &Registry,
    secret: &str,
    command: &str,
) -> Result<bool> {
    let vault = store.load()?;
    let entry = vault
        .get(secret)
        .ok_or_else(|| anyhow!("no secret named {secret:?}"))?;
    let def = find_command(registry, command)?;
    ensure!(
        def.manifest.permissions.vault.iter().any(|s| s == secret),
        "command {command:?} does not list {secret:?} in permissions.vault, so it could not use it anyway"
    );
    // The prompt and the fingerprint come from the same text, so what was shown is what gets allowed.
    let script = def.read_script()?;
    let fingerprint = approval::fingerprint(&def.manifest_source, &script);
    let (key, name) = (secret.to_string(), command.to_string());
    let review = approval::review(def, &script, secret, entry);
    if !term.review(&review.summary, &review.full, &review.question)? {
        log.record(Event::Declined { key, command: name });
        return Ok(false);
    }
    store.save(&vault.with_secret(secret, entry.with_command(command, fingerprint)))?;
    log.record(Event::Allowed { key, command: name });
    Ok(true)
}

fn find_command<'r>(registry: &'r Registry, name: &str) -> Result<&'r CommandDef> {
    if let Some(def) = registry.find(name) {
        return Ok(def);
    }
    match registry.problems.iter().find(|p| p.command == name) {
        Some(broken) => bail!(
            "command {name:?} is broken ({}). Fix it first: `tb self check`",
            broken.problem
        ),
        None => bail!("no command named {name:?}"),
    }
}

/// Takes a command's access away. Returns whether it was removed (the human may decline).
pub fn revoke(
    store: &dyn VaultStore,
    log: &dyn AuditLog,
    term: &dyn Terminal,
    secret: &str,
    command: &str,
) -> Result<bool> {
    let vault = store.load()?;
    let entry = vault
        .get(secret)
        .ok_or_else(|| anyhow!("no secret named {secret:?}"))?;
    ensure!(
        entry.commands.contains_key(command),
        "command {command:?} is not allowed to use {secret:?}"
    );
    if !term.confirm(&format!("Stop {command:?} from using secret {secret:?}?"))? {
        return Ok(false);
    }
    store.save(&vault.with_secret(secret, entry.without_command(command)))?;
    log.record(Event::Revoked { key: secret.to_string(), command: command.to_string() });
    Ok(true)
}

/// Returns whether the secret was deleted (the human may decline).
pub fn remove(store: &dyn VaultStore, log: &dyn AuditLog, term: &dyn Terminal, name: &str) -> Result<bool> {
    let vault = store.load()?;
    ensure!(vault.get(name).is_some(), "no secret named {name:?}");
    if !term.confirm(&format!("Delete secret {name:?}?"))? {
        return Ok(false);
    }
    store.save(&vault.without_secret(name))?;
    log.record(Event::Removed { key: name.to_string() });
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::fs;
    use std::path::Path;

    use super::*;
    use crate::manifest::Manifest;
    use crate::vault::VaultData;
    use crate::vault::approval::Access;
    use crate::vault::log::MemoryLog;
    use crate::vault::store::MemoryStore;

    struct FakeTerminal {
        secret: &'static str,
        confirm: bool,
        prompts: RefCell<Vec<String>>,
    }

    impl FakeTerminal {
        fn new(secret: &'static str, confirm: bool) -> Self {
            Self {
                secret,
                confirm,
                prompts: RefCell::new(Vec::new()),
            }
        }
    }

    impl Terminal for FakeTerminal {
        fn read_secret(&self, prompt: &str) -> Result<String> {
            self.prompts.borrow_mut().push(prompt.to_string());
            Ok(self.secret.to_string())
        }
        fn confirm(&self, prompt: &str) -> Result<bool> {
            self.prompts.borrow_mut().push(prompt.to_string());
            Ok(self.confirm)
        }
        fn review(&self, summary: &str, full: &str, question: &str) -> Result<bool> {
            self.prompts.borrow_mut().push(format!("{summary}\n{full}\n{question}"));
            Ok(self.confirm)
        }
    }

    fn term() -> FakeTerminal {
        FakeTerminal::new("  fake_stripe_0123456789\n", true)
    }

    fn rules<'a>(hosts: &'a [String], query_params: &'a [String]) -> Rules<'a> {
        Rules { hosts, query_params }
    }

    fn add_simple(store: &MemoryStore, term: &FakeTerminal, hosts: &[&str]) -> Result<SecretSummary> {
        let hosts: Vec<String> = hosts.iter().map(|h| h.to_string()).collect();
        add(store, &*MemoryLog::new(), term, &Registry::default(), "stripe", rules(&hosts, &[]))
    }

    fn command(root: &Path, name: &str, vault: &[&str]) -> CommandDef {
        let dir = root.join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("run.lua"), "return function() end").unwrap();
        let source = serde_json::json!({
            "name": name,
            "description": "test",
            "permissions": { "http": ["api.stripe.com"], "vault": vault },
        })
        .to_string();
        CommandDef {
            manifest: Manifest::parse(&source).unwrap(),
            manifest_source: source,
            dir,
        }
    }

    #[test]
    fn add_stores_trimmed_value_and_normalized_rules() {
        let store = MemoryStore::new(VaultData::default());
        let hosts = vec!["API.Stripe.com".to_string(), "127.0.0.1:8080".to_string()];
        let params = vec!["key".to_string()];
        let summary = add(&store, &*MemoryLog::new(), &term(), &Registry::default(), "stripe", rules(&hosts, &params)).unwrap();
        assert_eq!(summary.hosts, vec!["127.0.0.1:8080", "api.stripe.com"]);
        assert_eq!(summary.query_params, vec!["key"]);
        let saved = store.load().unwrap();
        assert_eq!(saved.get("stripe").unwrap().value.expose(), "fake_stripe_0123456789");
    }

    #[test]
    fn add_validates_input() {
        let store = MemoryStore::new(VaultData::default());
        let ok = vec!["x.com".to_string()];
        let none = Registry::default();
        assert!(add(&store, &*MemoryLog::new(), &term(), &none, "Bad Name", rules(&ok, &[])).is_err());
        assert!(add(&store, &*MemoryLog::new(), &term(), &none, "ok", rules(&[], &[])).is_err());
        assert!(add_simple(&store, &term(), &["https://x.com"]).is_err());
        assert!(add_simple(&store, &term(), &["localhost"]).is_err());
        assert!(add(&store, &*MemoryLog::new(), &term(), &none, "ok", rules(&ok, &["a b".to_string()])).is_err());
        let short = FakeTerminal::new("abc", true);
        assert!(add_simple(&store, &short, &["x.com"]).is_err());
        let empty = FakeTerminal::new("", true);
        assert!(add_simple(&store, &empty, &["x.com"]).is_err());
        assert!(store.load().unwrap().secrets.is_empty());
    }

    #[test]
    fn adding_again_with_an_empty_value_keeps_key_and_approvals() {
        let store = MemoryStore::new(VaultData::default());
        add_simple(&store, &term(), &["api.stripe.com"]).unwrap();
        let entry = store.load().unwrap().get("stripe").unwrap().with_command("charge", "fp".into());
        store.save(&store.load().unwrap().with_secret("stripe", entry)).unwrap();

        let keep = FakeTerminal::new("", true);
        let summary = add_simple(&store, &keep, &["api.stripe.com", "files.stripe.com"]).unwrap();
        assert_eq!(summary.hosts, vec!["api.stripe.com", "files.stripe.com"]);
        assert!(keep.prompts.borrow()[0].contains("leave empty to keep"));
        let saved = store.load().unwrap();
        let stripe = saved.get("stripe").unwrap();
        assert_eq!(stripe.value.expose(), "fake_stripe_0123456789");
        assert_eq!(stripe.commands.get("charge").map(String::as_str), Some("fp"));
    }

    #[test]
    fn list_never_includes_values() {
        let store = MemoryStore::new(VaultData::default());
        add_simple(&store, &term(), &["api.stripe.com"]).unwrap();
        let json = serde_json::to_string(&list(&store, &Registry::default()).unwrap()).unwrap();
        assert!(!json.contains("fake_stripe"));
        assert!(json.contains("stripe"));
    }

    #[test]
    fn allow_pins_the_command_and_shows_its_script() {
        let tmp = tempfile::tempdir().unwrap();
        let store = MemoryStore::new(VaultData::default());
        add_simple(&store, &term(), &["api.stripe.com"]).unwrap();
        let registry = Registry {
            commands: vec![command(tmp.path(), "charge", &["stripe"])],
            problems: vec![],
        };

        let decline = FakeTerminal::new("", false);
        assert!(!allow(&store, &*MemoryLog::new(), &decline, &registry, "stripe", "charge").unwrap());
        assert!(decline.prompts.borrow()[0].contains("return function() end"));
        assert!(store.load().unwrap().get("stripe").unwrap().commands.is_empty());

        assert!(allow(&store, &*MemoryLog::new(), &term(), &registry, "stripe", "charge").unwrap());
        let listed = list(&store, &registry).unwrap();
        assert_eq!(listed[0].commands[0].access, Access::Allowed);

        fs::write(tmp.path().join("charge/run.lua"), "return function() return 1 end").unwrap();
        let listed = list(&store, &registry).unwrap();
        assert_eq!(listed[0].commands[0].access, Access::Changed);
    }

    #[test]
    fn allow_refuses_unknown_broken_or_undeclaring_commands() {
        let tmp = tempfile::tempdir().unwrap();
        let store = MemoryStore::new(VaultData::default());
        add_simple(&store, &term(), &["api.stripe.com"]).unwrap();
        let registry = Registry {
            commands: vec![command(tmp.path(), "other", &[])],
            problems: vec![crate::registry::Problem {
                command: "broken".into(),
                problem: "missing run.lua".into(),
            }],
        };
        let err = |secret, cmd| allow(&store, &*MemoryLog::new(), &term(), &registry, secret, cmd).unwrap_err().to_string();
        assert!(err("stripe", "nope").contains("no command named"));
        assert!(err("stripe", "broken").contains("missing run.lua"));
        assert!(err("stripe", "other").contains("does not list"));
        assert!(err("github", "other").contains("no secret named"));
    }

    #[test]
    fn revoke_respects_confirmation() {
        let store = MemoryStore::new(VaultData::default());
        add_simple(&store, &term(), &["api.stripe.com"]).unwrap();
        let entry = store.load().unwrap().get("stripe").unwrap().with_command("charge", "fp".into());
        store.save(&store.load().unwrap().with_secret("stripe", entry)).unwrap();

        let decline = FakeTerminal::new("", false);
        assert!(!revoke(&store, &*MemoryLog::new(), &decline, "stripe", "charge").unwrap());
        assert!(revoke(&store, &*MemoryLog::new(), &term(), "stripe", "charge").unwrap());
        assert!(store.load().unwrap().get("stripe").unwrap().commands.is_empty());
        assert!(revoke(&store, &*MemoryLog::new(), &term(), "stripe", "charge").is_err());
    }

    #[test]
    fn remove_respects_confirmation() {
        let store = MemoryStore::new(VaultData::default());
        add_simple(&store, &term(), &["api.stripe.com"]).unwrap();

        let decline = FakeTerminal::new("", false);
        assert!(!remove(&store, &*MemoryLog::new(), &decline, "stripe").unwrap());
        assert!(store.load().unwrap().get("stripe").is_some());

        assert!(remove(&store, &*MemoryLog::new(), &term(), "stripe").unwrap());
        assert!(store.load().unwrap().get("stripe").is_none());
        assert!(remove(&store, &*MemoryLog::new(), &term(), "stripe").is_err());
    }

    #[test]
    fn every_change_is_logged_without_the_value() {
        let tmp = tempfile::tempdir().unwrap();
        let store = MemoryStore::new(VaultData::default());
        let log = MemoryLog::new();
        let hosts = vec!["api.stripe.com".to_string()];
        add(&store, &log, &term(), &Registry::default(), "stripe", rules(&hosts, &[])).unwrap();
        add(&store, &log, &FakeTerminal::new("", true), &Registry::default(), "stripe", rules(&hosts, &[])).unwrap();
        let registry = Registry { commands: vec![command(tmp.path(), "charge", &["stripe"])], problems: vec![] };
        allow(&store, &log, &FakeTerminal::new("", false), &registry, "stripe", "charge").unwrap();
        allow(&store, &log, &term(), &registry, "stripe", "charge").unwrap();
        revoke(&store, &log, &term(), "stripe", "charge").unwrap();
        remove(&store, &log, &term(), "stripe").unwrap();

        let events = log.0.borrow();
        let (key, command) = ("stripe".to_string(), "charge".to_string());
        assert!(matches!(&events[0], Event::Added { new_value: true, .. }), "{events:?}");
        assert!(matches!(&events[1], Event::Added { new_value: false, .. }), "{events:?}");
        assert_eq!(events[2], Event::Declined { key: key.clone(), command: command.clone() });
        assert_eq!(events[3], Event::Allowed { key: key.clone(), command: command.clone() });
        assert_eq!(events[4], Event::Revoked { key: key.clone(), command });
        assert_eq!(events[5], Event::Removed { key });
        assert_eq!(events.len(), 6);
        assert!(!format!("{events:?}").contains("fake_stripe"));
    }
}
