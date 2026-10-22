//! `tb self vault add|list|rm`. Adding and removing need a human at a terminal.

use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Write};

use anyhow::{Result, anyhow, ensure};

use super::{SecretEntry, SecretSummary, SecretValue, VaultStore, normalize_host};
use crate::manifest::is_valid_name;

/// Human input. The real one reads `/dev/tty`, which scripts and agents can't type into.
pub trait Terminal {
    fn read_secret(&self, prompt: &str) -> Result<String>;
    fn confirm(&self, prompt: &str) -> Result<bool>;
}

pub struct Tty;

impl Terminal for Tty {
    fn read_secret(&self, prompt: &str) -> Result<String> {
        rpassword::prompt_password(prompt).map_err(no_tty)
    }

    fn confirm(&self, prompt: &str) -> Result<bool> {
        let mut tty = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .map_err(no_tty)?;
        write!(tty, "{prompt} [y/N] ")?;
        tty.flush()?;
        let mut answer = String::new();
        BufReader::new(tty).read_line(&mut answer)?;
        Ok(matches!(answer.trim(), "y" | "Y" | "yes"))
    }
}

fn no_tty(err: io::Error) -> anyhow::Error {
    anyhow!(
        "this needs a human at an interactive terminal ({err}). Ask the user to run the command themselves in a terminal window"
    )
}

pub fn add(
    store: &dyn VaultStore,
    term: &dyn Terminal,
    name: &str,
    hosts: &[String],
) -> Result<SecretSummary> {
    ensure!(is_valid_name(name), "{name:?} is not a valid secret name (a-z, 0-9, '-', '_')");
    ensure!(!hosts.is_empty(), "give at least one --host the secret may be sent to");
    let hosts = hosts
        .iter()
        .map(|h| normalize_host(h))
        .collect::<Result<Vec<_>>>()?;
    let vault = store.load()?;
    let raw = term.read_secret(&format!("Value for {name} (input is hidden): "))?;
    let value = SecretValue::new(raw.trim().to_string())?;
    let entry = SecretEntry {
        value,
        hosts: hosts.clone(),
    };
    store.save(&vault.with_secret(name, entry))?;
    Ok(SecretSummary {
        name: name.to_string(),
        hosts,
    })
}

pub fn list(store: &dyn VaultStore) -> Result<Vec<SecretSummary>> {
    Ok(store.load()?.summaries())
}

/// Returns whether the secret was deleted (the human may decline).
pub fn remove(store: &dyn VaultStore, term: &dyn Terminal, name: &str) -> Result<bool> {
    let vault = store.load()?;
    ensure!(vault.get(name).is_some(), "no secret named {name:?}");
    if !term.confirm(&format!("Delete secret {name:?}?"))? {
        return Ok(false);
    }
    store.save(&vault.without_secret(name))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::VaultData;
    use crate::vault::store::MemoryStore;

    struct FakeTerminal {
        secret: &'static str,
        confirm: bool,
    }

    impl Terminal for FakeTerminal {
        fn read_secret(&self, _prompt: &str) -> Result<String> {
            Ok(self.secret.to_string())
        }
        fn confirm(&self, _prompt: &str) -> Result<bool> {
            Ok(self.confirm)
        }
    }

    const TERM: FakeTerminal = FakeTerminal {
        secret: "  fake_stripe_0123456789\n",
        confirm: true,
    };

    #[test]
    fn add_stores_trimmed_value_and_normalized_hosts() {
        let store = MemoryStore::new(VaultData::default());
        let summary = add(&store, &TERM, "stripe", &["API.Stripe.com".into()]).unwrap();
        assert_eq!(summary.hosts, vec!["api.stripe.com"]);
        let saved = store.load().unwrap();
        assert_eq!(saved.get("stripe").unwrap().value.expose(), "fake_stripe_0123456789");
    }

    #[test]
    fn add_validates_input() {
        let store = MemoryStore::new(VaultData::default());
        assert!(add(&store, &TERM, "Bad Name", &["x.com".into()]).is_err());
        assert!(add(&store, &TERM, "ok", &[]).is_err());
        assert!(add(&store, &TERM, "ok", &["https://x.com".into()]).is_err());
        let short = FakeTerminal { secret: "abc", confirm: true };
        assert!(add(&store, &short, "ok", &["x.com".into()]).is_err());
        assert!(store.load().unwrap().secrets.is_empty());
    }

    #[test]
    fn list_never_includes_values() {
        let store = MemoryStore::new(VaultData::default());
        add(&store, &TERM, "stripe", &["api.stripe.com".into()]).unwrap();
        let json = serde_json::to_string(&list(&store).unwrap()).unwrap();
        assert!(!json.contains("fake_stripe"));
        assert!(json.contains("stripe"));
    }

    #[test]
    fn remove_respects_confirmation() {
        let store = MemoryStore::new(VaultData::default());
        add(&store, &TERM, "stripe", &["api.stripe.com".into()]).unwrap();

        let decline = FakeTerminal { secret: "", confirm: false };
        assert!(!remove(&store, &decline, "stripe").unwrap());
        assert!(store.load().unwrap().get("stripe").is_some());

        assert!(remove(&store, &TERM, "stripe").unwrap());
        assert!(store.load().unwrap().get("stripe").is_none());
        assert!(remove(&store, &TERM, "stripe").is_err());
    }
}
