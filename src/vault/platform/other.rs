use anyhow::{Result, anyhow};

use crate::vault::VaultData;
use crate::vault::store::VaultStore;

const UNSUPPORTED: &str = "the vault only works on macOS for now. Here the system keyring hands stored keys to \
     any program you run, an AI agent included, which is what the vault exists to prevent. Commands that don't use \
     keys still work";

pub fn store() -> Box<dyn VaultStore> {
    Box::new(Unsupported)
}

struct Unsupported;

impl VaultStore for Unsupported {
    fn load(&self) -> Result<VaultData> {
        Err(anyhow!(UNSUPPORTED))
    }

    fn save(&self, _data: &VaultData, _change: &str) -> Result<()> {
        Err(anyhow!(UNSUPPORTED))
    }
}

pub fn ancestors() -> Vec<String> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_vault_refuses_to_keep_keys() {
        let err = store().load().unwrap_err().to_string();
        assert!(err.starts_with("the vault only works on macOS"), "{err}");
        assert!(store().save(&VaultData::default(), "test").is_err());
    }
}
