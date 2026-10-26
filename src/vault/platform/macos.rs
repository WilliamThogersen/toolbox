use anyhow::{Context, Result, anyhow};

use crate::sys::macos as sys;
use crate::vault::VaultData;
use crate::vault::store::{VaultStore, decode, encode};

const KEYCHAIN_SERVICE: &str = "toolbox";
const KEYCHAIN_ACCOUNT: &str = "vault";

const MAX_ANCESTORS: usize = 8;

pub fn store() -> Box<dyn VaultStore> {
    Box::new(KeychainStore)
}

struct KeychainStore;

impl KeychainStore {
    fn entry() -> Result<keyring::Entry> {
        let unavailable = |e: &keyring::Error| anyhow!("the macOS Keychain is not available: {e}");
        if let Err(e) = keyring::Entry::store_status() {
            return Err(unavailable(e));
        }
        keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT).map_err(|e| unavailable(&e))
    }
}

impl VaultStore for KeychainStore {
    fn load(&self) -> Result<VaultData> {
        match Self::entry()?.get_password() {
            Ok(raw) => decode(&raw).context("could not read the vault in the macOS Keychain"),
            Err(keyring::Error::NoEntry) => Ok(VaultData::default()),
            Err(e) => Err(anyhow!("could not read the vault from the macOS Keychain: {e}")),
        }
    }

    fn save(&self, data: &VaultData, change: &str) -> Result<()> {
        let raw = encode(data)?;
        sys::confirm_presence(change)?;
        Self::entry()?
            .set_password(&raw)
            .map_err(|e| anyhow!("could not write the vault to the macOS Keychain: {e}"))
    }
}

pub fn ancestors() -> Vec<String> {
    let home = dirs::home_dir().map(|home| home.display().to_string());
    let mut pid = sys::parent_pid();
    let mut found = Vec::new();
    while pid > 1 && found.len() < MAX_ANCESTORS {
        let Some((program, parent)) = sys::process(pid) else { break };
        let shown = match home.as_deref().and_then(|home| program.strip_prefix(home)) {
            Some(rest) if rest.starts_with('/') => format!("~{rest}"),
            _ => program,
        };
        found.push(shown);
        pid = parent;
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ancestors_name_the_programs_that_started_us() {
        let names = ancestors();
        assert!(!names.is_empty(), "the test runner has a parent");
        assert!(names.len() <= MAX_ANCESTORS);
        assert!(names.iter().all(|name| !name.is_empty()));
    }
}
