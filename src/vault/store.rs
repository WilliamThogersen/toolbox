//! Where the vault lives. The real store is the OS keychain.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, ensure};
use serde::{Deserialize, Serialize};

use super::{SecretEntry, SecretValue, VaultData};

const KEYCHAIN_SERVICE: &str = "toolbox";
const KEYCHAIN_ACCOUNT: &str = "vault";

/// Points toolbox at a plain-text vault file. Only for automated tests.
pub const TEST_VAULT_ENV: &str = "TOOLBOX_INSECURE_TEST_VAULT";

/// The stored shape. Version 2 keeps keys under `keys` where version 1 had
/// `secrets`, so toolbox 0.3.0, which knows nothing of command approvals or port
/// rules, reads an empty vault instead of using keys without them. Unknown fields
/// and versions are refused, so a newer toolbox's vault fails closed here too.
const FORMAT: u32 = 2;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    format: u32,
    keys: BTreeMap<String, SecretEntry>,
}

/// Version 1, written by toolbox 0.3.0 and older. Its approvals can't exist, so
/// every command needs a new one.
#[derive(Deserialize)]
struct StoredV1 {
    #[serde(default)]
    secrets: BTreeMap<String, EntryV1>,
}

#[derive(Deserialize)]
struct EntryV1 {
    value: SecretValue,
    hosts: Vec<String>,
}

pub fn encode(data: &VaultData) -> Result<String> {
    let stored = Stored {
        format: FORMAT,
        keys: data.secrets.clone(),
    };
    Ok(serde_json::to_string(&stored)?)
}

pub fn decode(raw: &str) -> Result<VaultData> {
    let value: serde_json::Value = serde_json::from_str(raw)?;
    if value.get("format").is_none() {
        let old: StoredV1 = serde_json::from_value(value)?;
        let secrets = old
            .secrets
            .into_iter()
            .map(|(name, entry)| {
                let upgraded = SecretEntry {
                    value: entry.value,
                    hosts: entry.hosts,
                    query_params: Vec::new(),
                    commands: BTreeMap::new(),
                };
                (name, upgraded)
            })
            .collect();
        return Ok(VaultData { secrets });
    }
    let stored: Stored = serde_json::from_value(value)?;
    ensure!(
        stored.format == FORMAT,
        "the vault was saved by a newer toolbox (format {}). Upgrade toolbox",
        stored.format
    );
    Ok(VaultData {
        secrets: stored.keys,
    })
}

pub trait VaultStore {
    fn load(&self) -> Result<VaultData>;
    fn save(&self, data: &VaultData) -> Result<()>;
}

pub fn default_store() -> Box<dyn VaultStore> {
    match std::env::var_os(TEST_VAULT_ENV) {
        Some(path) => Box::new(FileStore {
            path: PathBuf::from(path),
        }),
        None => Box::new(KeychainStore),
    }
}

/// The whole vault as one keychain item, so its host bindings can't be edited
/// from outside without the keychain's permission prompt.
pub struct KeychainStore;

impl KeychainStore {
    fn entry() -> Result<keyring::Entry> {
        keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
            .map_err(|e| anyhow!("the OS keychain is not available: {e}"))
    }
}

impl VaultStore for KeychainStore {
    fn load(&self) -> Result<VaultData> {
        match Self::entry()?.get_password() {
            Ok(raw) => decode(&raw).context("could not read the vault in the keychain"),
            Err(keyring::Error::NoEntry) => Ok(VaultData::default()),
            Err(e) => Err(anyhow!("could not read the vault from the keychain: {e}")),
        }
    }

    fn save(&self, data: &VaultData) -> Result<()> {
        let raw = encode(data)?;
        Self::entry()?
            .set_password(&raw)
            .map_err(|e| anyhow!("could not write the vault to the keychain: {e}"))
    }
}

/// Plain JSON file. Never use for real keys.
pub struct FileStore {
    pub path: PathBuf,
}

impl VaultStore for FileStore {
    fn load(&self) -> Result<VaultData> {
        if !self.path.exists() {
            return Ok(VaultData::default());
        }
        let raw = fs::read_to_string(&self.path)
            .with_context(|| format!("could not read {}", self.path.display()))?;
        decode(&raw).context("could not read the test vault file")
    }

    fn save(&self, data: &VaultData) -> Result<()> {
        fs::write(&self.path, encode(data)?)
            .with_context(|| format!("could not write {}", self.path.display()))
    }
}

#[cfg(test)]
pub struct MemoryStore {
    pub data: std::cell::RefCell<VaultData>,
}

#[cfg(test)]
impl MemoryStore {
    pub fn new(data: VaultData) -> Self {
        Self {
            data: std::cell::RefCell::new(data),
        }
    }
}

#[cfg(test)]
impl VaultStore for MemoryStore {
    fn load(&self) -> Result<VaultData> {
        Ok(self.data.borrow().clone())
    }

    fn save(&self, data: &VaultData) -> Result<()> {
        *self.data.borrow_mut() = data.clone();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_store_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileStore {
            path: tmp.path().join("vault.json"),
        };
        assert!(store.load().unwrap().secrets.is_empty());

        let data = VaultData::default().with_secret(
            "gh",
            SecretEntry {
                value: SecretValue::new("abcdefghij".into()).unwrap(),
                hosts: vec!["api.github.com".into()],
                query_params: vec!["key".into()],
                commands: [("stars".to_string(), "fp".to_string())].into(),
            },
        );
        store.save(&data).unwrap();
        let none = crate::registry::Registry::default();
        assert_eq!(store.load().unwrap().summaries(&none), data.summaries(&none));
    }

    #[test]
    fn version_1_loads_without_approvals() {
        let old = r#"{"secrets":{"gh":{"value":"super-secret-token","hosts":["127.0.0.1"]}}}"#;
        let vault = decode(old).unwrap();
        let gh = vault.get("gh").unwrap();
        assert_eq!(gh.hosts, vec!["127.0.0.1"]);
        assert!(gh.query_params.is_empty() && gh.commands.is_empty());

        let smuggled = r#"{"secrets":{"gh":{"value":"super-secret-token","hosts":["x.com"],"commands":{"a":"b"}}}}"#;
        assert!(decode(smuggled).unwrap().get("gh").unwrap().commands.is_empty());
    }

    #[test]
    fn version_2_hides_keys_from_toolbox_0_3() {
        let data = VaultData::default().with_secret(
            "gh",
            SecretEntry {
                value: SecretValue::new("super-secret-token".into()).unwrap(),
                hosts: vec!["api.github.com".into()],
                query_params: vec![],
                commands: BTreeMap::new(),
            },
        );
        let raw: serde_json::Value = serde_json::from_str(&encode(&data).unwrap()).unwrap();
        assert_eq!(raw["format"], 2);
        assert!(raw.get("secrets").is_none(), "0.3.0 reads `secrets`: {raw}");
        assert!(raw["keys"]["gh"].is_object());
    }

    #[test]
    fn newer_or_unknown_shapes_are_refused() {
        let base = r#""value":"super-secret-token","hosts":["x.com"]"#;
        for bad in [
            r#"{"format":3,"keys":{}}"#.to_string(),
            r#"{"format":2,"keys":{},"rules":{}}"#.to_string(),
            format!(r#"{{"format":2,"keys":{{"gh":{{{base},"methods":["GET"]}}}}}}"#),
        ] {
            assert!(decode(&bad).is_err(), "{bad}");
        }
    }
}
