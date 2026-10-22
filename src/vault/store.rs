//! Where the vault lives. The real store is the OS keychain.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};

use super::VaultData;

const KEYCHAIN_SERVICE: &str = "toolbox";
const KEYCHAIN_ACCOUNT: &str = "vault";

/// Points toolbox at a plain-text vault file. Only for automated tests.
pub const TEST_VAULT_ENV: &str = "TOOLBOX_INSECURE_TEST_VAULT";

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
            Ok(raw) => serde_json::from_str(&raw).context("the vault in the keychain is corrupt"),
            Err(keyring::Error::NoEntry) => Ok(VaultData::default()),
            Err(e) => Err(anyhow!("could not read the vault from the keychain: {e}")),
        }
    }

    fn save(&self, data: &VaultData) -> Result<()> {
        let raw = serde_json::to_string(data)?;
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
        serde_json::from_str(&raw).context("test vault file is corrupt")
    }

    fn save(&self, data: &VaultData) -> Result<()> {
        fs::write(&self.path, serde_json::to_string_pretty(data)?)
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
    use crate::vault::{SecretEntry, SecretValue};

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
            },
        );
        store.save(&data).unwrap();
        assert_eq!(store.load().unwrap().summaries(), data.summaries());
    }
}
