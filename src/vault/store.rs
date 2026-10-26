use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::{SecretEntry, SecretValue, VaultData, platform};

pub const TEST_VAULT_ENV: &str = "TOOLBOX_INSECURE_TEST_VAULT";
pub const TEST_CONFIRM_ENV: &str = "TOOLBOX_INSECURE_TEST_CONFIRM";

const FORMAT: u32 = 4;

const READABLE_FORMATS: [u32; 3] = [2, 3, FORMAT];

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    format: u32,
    keys: BTreeMap<String, SecretEntry>,
}

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
            .map(|(name, entry)| (name, SecretEntry::new(entry.value, entry.hosts)))
            .collect();
        return Ok(VaultData { secrets });
    }
    let stored: Stored = serde_json::from_value(value)?;
    ensure!(
        READABLE_FORMATS.contains(&stored.format),
        "the vault was saved by a newer toolbox (format {}). Upgrade toolbox",
        stored.format
    );
    Ok(VaultData {
        secrets: stored.keys,
    })
}

pub trait VaultStore {
    fn load(&self) -> Result<VaultData>;
    fn save(&self, data: &VaultData, change: &str) -> Result<()>;
    fn confirm_use(&self, request: &str) -> Result<()>;
}

impl<T: VaultStore + ?Sized> VaultStore for std::rc::Rc<T> {
    fn load(&self) -> Result<VaultData> {
        (**self).load()
    }

    fn save(&self, data: &VaultData, change: &str) -> Result<()> {
        (**self).save(data, change)
    }

    fn confirm_use(&self, request: &str) -> Result<()> {
        (**self).confirm_use(request)
    }
}

pub fn default_store() -> Box<dyn VaultStore> {
    match std::env::var_os(TEST_VAULT_ENV) {
        Some(path) => Box::new(FileStore {
            path: PathBuf::from(path),
        }),
        None => platform::store(),
    }
}

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

    fn save(&self, data: &VaultData, _change: &str) -> Result<()> {
        fs::write(&self.path, encode(data)?)
            .with_context(|| format!("could not write {}", self.path.display()))
    }

    fn confirm_use(&self, request: &str) -> Result<()> {
        eprintln!("toolbox test vault: would ask for Touch ID to {request}");
        ensure!(
            std::env::var_os(TEST_CONFIRM_ENV).is_some_and(|answer| answer == "yes"),
            "declined in the test vault ({TEST_CONFIRM_ENV} is not yes)"
        );
        Ok(())
    }
}

#[cfg(test)]
pub struct MemoryStore {
    pub data: std::cell::RefCell<VaultData>,
    pub changes: std::cell::RefCell<Vec<String>>,
    pub asked: std::cell::RefCell<Vec<String>>,
    pub confirm: std::cell::Cell<bool>,
}

#[cfg(test)]
impl MemoryStore {
    pub fn new(data: VaultData) -> Self {
        Self {
            data: std::cell::RefCell::new(data),
            changes: std::cell::RefCell::new(Vec::new()),
            asked: std::cell::RefCell::new(Vec::new()),
            confirm: std::cell::Cell::new(true),
        }
    }
}

#[cfg(test)]
impl VaultStore for MemoryStore {
    fn load(&self) -> Result<VaultData> {
        Ok(self.data.borrow().clone())
    }

    fn save(&self, data: &VaultData, change: &str) -> Result<()> {
        *self.data.borrow_mut() = data.clone();
        self.changes.borrow_mut().push(change.to_string());
        Ok(())
    }

    fn confirm_use(&self, request: &str) -> Result<()> {
        self.asked.borrow_mut().push(request.to_string());
        ensure!(self.confirm.get(), "Canceled by user.");
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
                query_params: vec!["key".into()],
                methods: vec!["GET".into()],
                paths: vec!["/repos".into()],
                confirm: vec!["writes".into()],
                commands: [("stars".to_string(), "fp".to_string())].into(),
                ..SecretEntry::new(SecretValue::new("abcdefghij".into()).unwrap(), vec!["api.github.com".into()])
            },
        );
        store.save(&data, "test").unwrap();
        let none = crate::command::registry::Registry::default();
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
    fn saved_vaults_hide_keys_from_older_toolboxes() {
        let data = VaultData::default().with_secret(
            "gh",
            SecretEntry::new(SecretValue::new("super-secret-token".into()).unwrap(), vec!["api.github.com".into()]),
        );
        let raw: serde_json::Value = serde_json::from_str(&encode(&data).unwrap()).unwrap();
        assert_eq!(raw["format"], 4, "0.7.0 and older only open formats 2 and 3, so they can't skip method, path and confirm rules");
        assert!(raw.get("secrets").is_none(), "0.3.0 reads `secrets`: {raw}");
        assert!(raw["keys"]["gh"].is_object());
    }

    #[test]
    fn formats_2_and_3_still_load() {
        for format in [2, 3] {
            let raw = format!(r#"{{"format":{format},"keys":{{"gh":{{"value":"super-secret-token","hosts":["x.com"]}}}}}}"#);
            let vault = decode(&raw).unwrap();
            let gh = vault.get("gh").unwrap();
            assert_eq!(gh.hosts, vec!["x.com"]);
            assert!(gh.methods.is_empty() && gh.paths.is_empty() && gh.confirm.is_empty());
        }
    }

    #[test]
    fn newer_or_unknown_shapes_are_refused() {
        let base = r#""value":"super-secret-token","hosts":["x.com"]"#;
        for bad in [
            r#"{"format":5,"keys":{}}"#.to_string(),
            r#"{"format":4,"keys":{},"rules":{}}"#.to_string(),
            format!(r#"{{"format":4,"keys":{{"gh":{{{base},"colors":["red"]}}}}}}"#),
        ] {
            assert!(decode(&bad).is_err(), "{bad}");
        }
    }
}
