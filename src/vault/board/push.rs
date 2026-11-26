use anyhow::{Result, bail, ensure};
use serde::Serialize;

use super::Connection;
use crate::vault::commands::Terminal;
use crate::vault::{SecretEntry, SecretValue, VaultData, VaultStore};

#[derive(Debug, Default, Serialize, PartialEq)]
pub struct PushReport {
    pub pushed: Vec<String>,
    pub skipped: Vec<Skipped>,
    pub failed: Vec<Skipped>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Skipped {
    pub name: String,
    pub reason: String,
}

fn skipped(name: &str, reason: &str) -> Skipped {
    Skipped { name: name.to_string(), reason: reason.to_string() }
}

pub fn push(local: &dyn VaultStore, board: &Connection, term: &dyn Terminal, names: &[String]) -> Result<PushReport> {
    let vault = local.load()?;
    for name in names {
        ensure!(vault.get(name).is_some(), "no secret named {name:?} on this Mac");
    }
    let mut report = PushReport::default();
    let mut candidates = Vec::new();
    for (name, entry) in &vault.secrets {
        if !names.is_empty() && !names.contains(name) {
            continue;
        }
        if entry.oauth.is_some() {
            report.skipped.push(skipped(name, "a sign-in key stays on this Mac for now"));
        } else if entry.remote {
            report.skipped.push(skipped(name, "the board already holds it"));
        } else {
            candidates.push((name.as_str(), entry));
        }
    }
    if candidates.is_empty() {
        return Ok(report);
    }
    let list = candidates.iter().map(|(name, _)| *name).collect::<Vec<_>>().join(", ");
    let question = format!(
        "Move {list} to the board at {}? Each key is deleted from this Mac once the board has confirmed it.",
        board.base()
    );
    if !term.confirm(&question)? {
        bail!("declined: nothing was sent");
    }
    local.confirm_use(&format!("send the API keys {list} to the board at {} and delete them from this Mac", board.base()))?;
    let mut moved = Vec::new();
    for (name, entry) in candidates {
        match board.put_secret(name, entry.value.expose(), &entry.hosts, &entry.methods, &entry.paths) {
            Ok(()) => moved.push(name.to_string()),
            Err(err) => report.failed.push(skipped(name, &format!("{err:#}"))),
        }
    }
    if !moved.is_empty() {
        let change = format!("delete the API keys {} from this Mac, now that the board holds them", moved.join(", "));
        local.save(&without_values(&vault, &moved), &change)?;
    }
    report.pushed = moved;
    Ok(report)
}

fn without_values(vault: &VaultData, moved: &[String]) -> VaultData {
    let secrets = vault
        .secrets
        .iter()
        .map(|(name, entry)| {
            let entry = if moved.contains(name) {
                SecretEntry { remote: true, value: SecretValue::absent(), ..entry.clone() }
            } else {
                entry.clone()
            };
            (name.clone(), entry)
        })
        .collect();
    VaultData { secrets }
}
