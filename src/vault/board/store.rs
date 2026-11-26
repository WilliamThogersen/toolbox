use std::rc::Rc;

use anyhow::Result;

use super::{BoardSecret, Link};
use crate::vault::{SecretEntry, VaultData, VaultStore};

pub struct BoardStore {
    inner: Box<dyn VaultStore>,
    link: Rc<Link>,
}

impl BoardStore {
    pub fn new(inner: Box<dyn VaultStore>, link: Rc<Link>) -> Self {
        Self { inner, link }
    }
}

impl VaultStore for BoardStore {
    fn load(&self) -> Result<VaultData> {
        let local = self.inner.load()?;
        let Some(connection) = self.link.connection() else {
            return Ok(local);
        };
        match connection.secrets() {
            Ok(listing) => Ok(overlay(local, &listing)),
            Err(err) => {
                eprintln!("toolbox: showing only this Mac's own keys: {err:#}");
                Ok(local)
            }
        }
    }

    fn save(&self, data: &VaultData, change: &str) -> Result<()> {
        self.inner.save(&without_bare_remote(data), change)
    }

    fn confirm_use(&self, request: &str) -> Result<()> {
        self.inner.confirm_use(request)
    }
}

pub fn overlay(local: VaultData, listing: &[BoardSecret]) -> VaultData {
    let mut secrets = local.secrets;
    for held in listing {
        match secrets.get_mut(&held.name) {
            Some(entry) if entry.remote => {
                entry.hosts.clone_from(&held.hosts);
                entry.methods.clone_from(&held.methods);
                entry.paths.clone_from(&held.paths);
            }
            Some(_) => {}
            None => {
                let mut entry = SecretEntry::held_by_board(held.hosts.clone());
                entry.methods.clone_from(&held.methods);
                entry.paths.clone_from(&held.paths);
                secrets.insert(held.name.clone(), entry);
            }
        }
    }
    VaultData { secrets }
}

fn without_bare_remote(data: &VaultData) -> VaultData {
    let secrets = data
        .secrets
        .iter()
        .filter(|(_, entry)| {
            !(entry.remote && entry.commands.is_empty() && entry.confirm.is_empty() && entry.query_params.is_empty())
        })
        .map(|(name, entry)| (name.clone(), entry.clone()))
        .collect();
    VaultData { secrets }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::SecretValue;
    use crate::vault::store::MemoryStore;

    fn held(name: &str, hosts: &[&str]) -> BoardSecret {
        BoardSecret {
            name: name.into(),
            hosts: hosts.iter().map(ToString::to_string).collect(),
            methods: vec![],
            paths: vec![],
        }
    }

    fn local(value: &str) -> SecretEntry {
        SecretEntry::new(SecretValue::new(value.into()).unwrap(), vec!["old.example.com".into()])
    }

    #[test]
    fn board_secrets_appear_without_a_value() {
        let merged = overlay(VaultData::default(), &[held("coolify", &["coolify.example.com"])]);
        let entry = merged.get("coolify").unwrap();
        assert!(entry.remote && entry.commands.is_empty());
        assert_eq!(entry.hosts, ["coolify.example.com"]);
        assert!(entry.secret_values().is_empty());
    }

    #[test]
    fn the_boards_hosts_replace_the_cached_ones_but_approvals_stay() {
        let mut cached = SecretEntry::held_by_board(vec!["old.example.com".into()]).with_command("deploy", "abc".into());
        cached.confirm = vec!["writes".into()];
        let merged = overlay(VaultData::default().with_secret("coolify", cached), &[held("coolify", &["new.example.com"])]);
        let entry = merged.get("coolify").unwrap();
        assert_eq!(entry.hosts, ["new.example.com"]);
        assert_eq!(entry.commands.get("deploy").map(String::as_str), Some("abc"));
        assert_eq!(entry.confirm, ["writes"]);
    }

    #[test]
    fn a_key_still_on_this_mac_is_not_taken_over_by_the_board() {
        let merged = overlay(VaultData::default().with_secret("k", local("fake_value_12345")), &[held("k", &["evil.test"])]);
        let entry = merged.get("k").unwrap();
        assert!(!entry.remote);
        assert_eq!(entry.hosts, ["old.example.com"]);
    }

    #[test]
    fn saving_drops_board_entries_nobody_approved_or_tuned() {
        let kept = SecretEntry::held_by_board(vec!["a.example.com".into()]).with_command("deploy", "abc".into());
        let bare = SecretEntry::held_by_board(vec!["b.example.com".into()]);
        let data = VaultData::default().with_secret("kept", kept).with_secret("bare", bare);
        let inner = std::rc::Rc::new(MemoryStore::new(VaultData::default()));
        let store = BoardStore::new(Box::new(std::rc::Rc::clone(&inner)), Link::none());
        store.save(&data, "test").unwrap();
        let saved = inner.load().unwrap();
        assert!(saved.get("kept").is_some() && saved.get("bare").is_none());
    }
}
