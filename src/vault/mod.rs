//! The vault: API keys that commands can use without ever seeing them.
//!
//! Scripts only get placeholders like `{{vault:github}}`. The HTTP layer swaps
//! in the real value while sending, and only to hosts the human allowed.

pub mod commands;
pub mod inject;
pub mod store;

use std::collections::BTreeMap;
use std::fmt;

use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};

pub use store::{VaultStore, default_store};

/// Shorter values would make response redaction mangle normal text.
const MIN_SECRET_LEN: usize = 8;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VaultData {
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    pub value: SecretValue,
    /// Hosts this secret may be sent to. Set by the human, never by scripts.
    pub hosts: Vec<String>,
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

/// What may be shown about a secret: its name and allowed hosts.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SecretSummary {
    pub name: String,
    pub hosts: Vec<String>,
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

    pub fn summaries(&self) -> Vec<SecretSummary> {
        self.secrets
            .iter()
            .map(|(name, entry)| SecretSummary {
                name: name.clone(),
                hosts: entry.hosts.clone(),
            })
            .collect()
    }
}

/// Accepts a bare hostname like `api.github.com` and returns it lowercased.
pub fn normalize_host(raw: &str) -> Result<String> {
    let host = raw.trim().to_ascii_lowercase();
    let valid_chars = host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    if host.is_empty() || !valid_chars || host.starts_with('.') || host.ends_with('.') {
        bail!("{raw:?} is not a valid host. Use a bare hostname like api.github.com (no scheme, port, path or wildcard)");
    }
    Ok(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(value: &str) -> SecretEntry {
        SecretEntry {
            value: SecretValue::new(value.to_string()).unwrap(),
            hosts: vec!["api.example.com".to_string()],
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
        let json = serde_json::to_string(&vault.summaries()).unwrap();
        assert_eq!(json, r#"[{"name":"gh","hosts":["api.example.com"]}]"#);
    }

    #[test]
    fn secret_value_rules() {
        assert!(SecretValue::new("short".into()).is_err());
        assert!(SecretValue::new("has\nnewline-inside".into()).is_err());
        assert!(SecretValue::new(" padded-value ".into()).is_err());
        assert!(SecretValue::new("fake_token_abcdefgh".into()).is_ok());
    }

    #[test]
    fn host_rules() {
        assert_eq!(normalize_host(" API.GitHub.com ").unwrap(), "api.github.com");
        assert_eq!(normalize_host("127.0.0.1").unwrap(), "127.0.0.1");
        for bad in ["", "*", "*.github.com", "https://x.com", "x.com/path", "x.com:443", ".x.com"] {
            assert!(normalize_host(bad).is_err(), "{bad} should be rejected");
        }
    }
}
