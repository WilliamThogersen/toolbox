//! The vault: API keys that commands can use without ever seeing them.
//!
//! Scripts only get placeholders like `{{vault:github}}`. The HTTP layer swaps
//! in the real value while sending, only to hosts the human allowed, and only
//! for commands the human approved.

pub mod approval;
pub mod commands;
pub mod hosts;
pub mod inject;
pub mod log;
pub mod store;

use std::collections::BTreeMap;
use std::fmt;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

pub use store::{VaultStore, default_store};

use crate::registry::Registry;
use approval::CommandAccess;

/// Shorter values would make response redaction mangle normal text.
pub(crate) const MIN_SECRET_LEN: usize = 8;

/// The vault in memory. How it is stored is up to `store` (see `store::encode`).
#[derive(Debug, Clone, Default)]
pub struct VaultData {
    pub secrets: BTreeMap<String, SecretEntry>,
}

/// Everything here is set by the human at a terminal, never by scripts. Unknown
/// fields are refused, so a newer toolbox's rules are never silently ignored.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretEntry {
    pub value: SecretValue,
    /// Where it may be sent: `api.github.com` (any port) or `localhost:8080`.
    pub hosts: Vec<String>,
    /// Query parameters it may be sent in, like `key` for `?key=...`. Empty means headers only.
    #[serde(default)]
    pub query_params: Vec<String>,
    /// Commands allowed to use it, each with the fingerprint of the files the human approved.
    #[serde(default)]
    pub commands: BTreeMap<String, String>,
}

impl SecretEntry {
    pub fn with_command(&self, name: &str, fingerprint: String) -> Self {
        let mut commands = self.commands.clone();
        commands.insert(name.to_string(), fingerprint);
        Self {
            commands,
            ..self.clone()
        }
    }

    pub fn without_command(&self, name: &str) -> Self {
        let commands = self
            .commands
            .iter()
            .filter(|(key, _)| key.as_str() != name)
            .map(|(key, fingerprint)| (key.clone(), fingerprint.clone()))
            .collect();
        Self {
            commands,
            ..self.clone()
        }
    }

    pub fn summary(&self, name: &str, registry: &Registry) -> SecretSummary {
        SecretSummary {
            name: name.to_string(),
            hosts: self.hosts.clone(),
            query_params: self.query_params.clone(),
            commands: approval::access(name, self, registry),
        }
    }
}

/// A secret string whose `Debug` output never shows the value.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretValue(String);

impl SecretValue {
    pub fn new(raw: String) -> Result<Self> {
        ensure!(
            raw.chars().count() >= MIN_SECRET_LEN,
            "secret must be at least {MIN_SECRET_LEN} characters"
        );
        ensure!(
            !raw.chars().any(char::is_control),
            "secret must not contain control characters or line breaks"
        );
        ensure!(
            raw.trim() == raw,
            "secret must not start or end with whitespace"
        );
        Ok(Self(raw))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue([REDACTED])")
    }
}

/// What may be shown about a secret: everything but its value.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SecretSummary {
    pub name: String,
    pub hosts: Vec<String>,
    pub query_params: Vec<String>,
    pub commands: Vec<CommandAccess>,
}

impl VaultData {
    pub fn get(&self, name: &str) -> Option<&SecretEntry> {
        self.secrets.get(name)
    }

    pub fn with_secret(&self, name: &str, entry: SecretEntry) -> Self {
        let mut secrets = self.secrets.clone();
        secrets.insert(name.to_string(), entry);
        Self { secrets }
    }

    pub fn without_secret(&self, name: &str) -> Self {
        let secrets = self
            .secrets
            .iter()
            .filter(|(key, _)| key.as_str() != name)
            .map(|(key, entry)| (key.clone(), entry.clone()))
            .collect();
        Self { secrets }
    }

    pub fn summaries(&self, registry: &Registry) -> Vec<SecretSummary> {
        self.secrets
            .iter()
            .map(|(name, entry)| entry.summary(name, registry))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(value: &str) -> SecretEntry {
        SecretEntry {
            value: SecretValue::new(value.to_string()).unwrap(),
            hosts: vec!["api.example.com".to_string()],
            query_params: vec![],
            commands: BTreeMap::new(),
        }
    }

    #[test]
    fn debug_never_shows_the_value() {
        let vault = VaultData::default().with_secret("gh", entry("super-secret-token"));
        let printed = format!("{vault:?}");
        assert!(!printed.contains("super-secret-token"));
        assert!(printed.contains("REDACTED"));
    }

    #[test]
    fn with_and_without_secret_do_not_mutate() {
        let empty = VaultData::default();
        let one = empty.with_secret("gh", entry("super-secret-token"));
        assert!(empty.secrets.is_empty());
        assert!(one.get("gh").is_some());

        let none = one.without_secret("gh");
        assert!(one.get("gh").is_some());
        assert!(none.get("gh").is_none());
    }

    #[test]
    fn summaries_have_no_values() {
        let vault = VaultData::default().with_secret("gh", entry("super-secret-token"));
        let json = serde_json::to_string(&vault.summaries(&Registry::default())).unwrap();
        assert_eq!(
            json,
            r#"[{"name":"gh","hosts":["api.example.com"],"query_params":[],"commands":[]}]"#
        );
    }

    #[test]
    fn command_grants_do_not_mutate() {
        let base = entry("super-secret-token");
        let granted = base.with_command("stars", "abc".into());
        assert!(base.commands.is_empty());
        assert_eq!(granted.commands.get("stars").map(String::as_str), Some("abc"));
        let revoked = granted.without_command("stars");
        assert!(granted.commands.contains_key("stars"));
        assert!(revoked.commands.is_empty());
        assert_eq!(revoked.hosts, base.hosts);
    }

    #[test]
    fn secret_value_rules() {
        assert!(SecretValue::new("short".into()).is_err());
        assert!(SecretValue::new("has\nnewline-inside".into()).is_err());
        assert!(SecretValue::new(" padded-value ".into()).is_err());
        assert!(SecretValue::new("fake_token_abcdefgh".into()).is_ok());
    }
}
