use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

use super::VaultStore;
use super::hosts::{normalize_host, normalize_query_param};
use super::log::{AuditLog, Event};
use super::names::{self, NAME_RULES, is_secret_name};
use crate::cli::paths;
use crate::command::registry::Registry;
use crate::cli::screen::printable;

pub const REQUESTS_FILE: &str = "vault-requests.json";
const MAX_REQUESTS: usize = 20;
const MAX_HOSTS: usize = 5;
const MAX_QUERY_PARAMS: usize = 5;
const MAX_TEXT_LEN: usize = 200;

pub fn default_path() -> Result<PathBuf> {
    Ok(paths::toolbox_home()?.join(REQUESTS_FILE))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRequest {
    pub name: String,
    pub hosts: Vec<String>,
    #[serde(default)]
    pub query_params: Vec<String>,
    pub why: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl KeyRequest {
    pub fn new(name: &str, hosts: &[String], query_params: &[String], why: &str, note: Option<&str>) -> Result<Self> {
        ensure!(is_secret_name(name), "{name:?} is not a valid key name ({NAME_RULES})");
        ensure!(!hosts.is_empty(), "give at least one --host the key may be sent to");
        let hosts: BTreeSet<String> = hosts.iter().map(|h| normalize_host(h)).collect::<Result<_>>()?;
        let query_params: BTreeSet<String> =
            query_params.iter().map(|p| normalize_query_param(p)).collect::<Result<_>>()?;
        ensure!(hosts.len() <= MAX_HOSTS, "a request may name at most {MAX_HOSTS} hosts");
        ensure!(query_params.len() <= MAX_QUERY_PARAMS, "a request may name at most {MAX_QUERY_PARAMS} query parameters");
        let why = checked_text("--why", why)?;
        ensure!(!why.is_empty(), "say with --why what the key is needed for, like \"Run Lighthouse audits through the PageSpeed API\"");
        let note = note.map(|note| checked_text("--note", note)).transpose()?;
        Ok(Self {
            name: name.to_string(),
            hosts: hosts.into_iter().collect(),
            query_params: query_params.into_iter().collect(),
            why,
            note: note.filter(|note| !note.is_empty()),
        })
    }

    fn checked(&self) -> Result<Self> {
        Self::new(&self.name, &self.hosts, &self.query_params, &self.why, self.note.as_deref())
    }
}

fn checked_text(flag: &str, raw: &str) -> Result<String> {
    ensure!(
        !raw.chars().any(char::is_control) && printable(raw) == raw,
        "{flag} must be one line of plain text"
    );
    let text = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    ensure!(text.chars().count() <= MAX_TEXT_LEN, "{flag} must be at most {MAX_TEXT_LEN} characters");
    Ok(text)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    requests: Vec<serde_json::Value>,
}

#[derive(Serialize)]
struct FileOut<'a> {
    requests: &'a [KeyRequest],
}

#[derive(Debug, Default)]
pub struct Waiting {
    pub requests: Vec<KeyRequest>,
    pub ignored: usize,
}

pub fn load(path: &Path) -> Result<Waiting> {
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Waiting::default()),
        Err(err) => return Err(err).with_context(|| format!("could not read {}", path.display())),
    };
    let file: RawFile = serde_json::from_str(&raw)
        .with_context(|| format!("{} is broken. Delete it and ask the agent to request the keys again", path.display()))?;
    let valid: Vec<KeyRequest> = file
        .requests
        .iter()
        .filter_map(|entry| serde_json::from_value::<KeyRequest>(entry.clone()).ok())
        .filter_map(|entry| entry.checked().ok())
        .collect();
    let requests: Vec<KeyRequest> = valid
        .iter()
        .enumerate()
        .filter(|(i, entry)| !valid.iter().take(*i).any(|earlier| earlier.name == entry.name))
        .map(|(_, entry)| entry.clone())
        .take(MAX_REQUESTS)
        .collect();
    Ok(Waiting { ignored: file.requests.len() - requests.len(), requests })
}

pub fn save(path: &Path, requests: &[KeyRequest]) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let text = serde_json::to_string_pretty(&FileOut { requests })?;
    let temp = path.with_extension("json.tmp");
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&temp)
        .with_context(|| format!("could not write {}", temp.display()))?;
    file.write_all(text.as_bytes())?;
    fs::rename(&temp, path).with_context(|| format!("could not write {}", path.display()))
}

pub fn with_request(requests: &[KeyRequest], request: KeyRequest) -> Vec<KeyRequest> {
    let mut updated: Vec<KeyRequest> = requests.iter().filter(|old| old.name != request.name).cloned().collect();
    updated.push(request);
    updated
}

#[derive(Debug, Serialize)]
#[expect(clippy::struct_field_names, reason = "the field names are the JSON the agent reads")]
pub struct Requested {
    pub requested: String,
    pub hosts: Vec<String>,
    pub query_params: Vec<String>,
    pub why: String,
    pub used_by: Vec<String>,
    pub next: String,
}

pub fn request(
    store: &dyn VaultStore,
    log: &dyn AuditLog,
    registry: &Registry,
    path: &Path,
    wanted: KeyRequest,
) -> Result<Requested> {
    let name = wanted.name.clone();
    if store.load()?.get(&name).is_some() {
        bail!(
            "{name:?} is already in the vault. If it needs other hosts, ask the user to run `tb self vault add {name} --host <host>` in their own terminal"
        );
    }
    let waiting = load(path)?.requests;
    let replaces = waiting.iter().any(|old| old.name == name);
    ensure!(
        replaces || waiting.len() < MAX_REQUESTS,
        "{MAX_REQUESTS} key requests are already waiting. Ask the user to run `tb self vault setup` in their own terminal first"
    );
    save(path, &with_request(&waiting, wanted.clone()))?;
    log.record(Event::Requested {
        key: name.clone(),
        hosts: wanted.hosts.clone(),
        query_params: wanted.query_params.clone(),
        why: wanted.why.clone(),
    });
    let used_by = registry
        .commands
        .iter()
        .filter(|def| names::declared(&def.manifest.permissions.vault, &name))
        .map(|def| def.manifest.name.clone())
        .collect();
    Ok(Requested {
        requested: name,
        hosts: wanted.hosts,
        query_params: wanted.query_params,
        why: wanted.why,
        used_by,
        next: "Ask the user to run `tb self vault setup` in their own terminal. It asks them for the key and lets them review the commands that use it".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::log::MemoryLog;
    use crate::vault::store::MemoryStore;
    use crate::vault::{SecretEntry, SecretValue, VaultData};

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(std::string::ToString::to_string).collect()
    }

    fn wanted(name: &str) -> KeyRequest {
        let hosts = strings(&["API.Example.com"]);
        KeyRequest::new(name, &hosts, &strings(&["key"]), "Geocode addresses", Some("Get it at https://example.com/keys")).unwrap()
    }

    #[test]
    fn requests_are_checked_like_vault_add() {
        let req = wanted("maps");
        assert_eq!(req.hosts, vec!["api.example.com"]);
        assert_eq!(req.query_params, vec!["key"]);
        let hosts = strings(&["x.com"]);
        for (why, bad) in [("", "say with --why"), ("   ", "say with --why"), ("two\nlines", "one line"), ("a\u{202e}b", "plain text")] {
            let err = KeyRequest::new("ok", &hosts, &[], why, None).unwrap_err().to_string();
            assert!(err.contains(bad), "{why:?}: {err}");
        }
        for (name, hosts, params, note) in [
            ("Bad Name", hosts.clone(), vec![], None),
            ("ok", vec![], vec![], None),
            ("ok", strings(&["https://x.com"]), vec![], None),
            ("ok", strings(&["localhost:8080"]), vec![], None),
            ("ok", hosts.clone(), strings(&["a b"]), None),
            ("ok", hosts.clone(), vec![], Some("line\nbreak")),
            ("ok", hosts.clone(), vec![], Some("\u{1b}[2Khidden")),
            ("ok", hosts.clone(), vec![], Some("evil\u{202e}txt")),
            ("ok", hosts.clone(), vec![], Some("zero\u{200b}width")),
            ("ok", strings(&["a.com", "b.com", "c.com", "d.com", "e.com", "f.com"]), vec![], None),
            ("ok", hosts.clone(), strings(&["a", "b", "c", "d", "e", "f"]), None),
        ] {
            assert!(KeyRequest::new(name, &hosts, &params, "why", note).is_err(), "{name} {hosts:?} {params:?} {note:?}");
        }
        let long = "x".repeat(MAX_TEXT_LEN + 1);
        assert!(KeyRequest::new("ok", &hosts, &[], "why", Some(&long)).is_err());
        assert!(KeyRequest::new("ok", &hosts, &[], &long, None).is_err());
        assert_eq!(KeyRequest::new("ok", &hosts, &[], "why", Some("  ")).unwrap().note, None);
        let padded = format!("Get it{}at x.com", " ".repeat(150));
        let req = KeyRequest::new("ok", &hosts, &[], &padded, Some(&padded)).unwrap();
        assert_eq!((req.why.as_str(), req.note.as_deref()), ("Get it at x.com", Some("Get it at x.com")), "spaces can't fake extra lines");
        let danish = KeyRequest::new("ok", &hosts, &[], "Hent nøglen på x.com", None).unwrap();
        assert_eq!(danish.why, "Hent nøglen på x.com");
    }

    #[test]
    fn the_file_round_trips_and_a_missing_one_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(REQUESTS_FILE);
        assert!(load(&path).unwrap().requests.is_empty());
        let list = with_request(&with_request(&[], wanted("maps")), wanted("github/work"));
        save(&path, &list).unwrap();
        assert_eq!(load(&path).unwrap().requests, list);
        let mode = fs::metadata(&path).unwrap().permissions();
        assert_eq!(std::os::unix::fs::PermissionsExt::mode(&mode) & 0o777, 0o600);
    }

    #[test]
    fn edited_files_are_checked_again_entry_by_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(REQUESTS_FILE);
        let good = r#"{"name":"maps","hosts":["x.com"],"why":"Maps"}"#;
        let entries = [
            r#"{"name":"bad","hosts":["localhost"],"why":"x"}"#.to_string(),
            r#"{"name":"bad","hosts":["x.com"],"why":"x","commands":{"a":"b"}}"#.to_string(),
            r#"{"name":"bad","hosts":["x.com"],"why":"x","note":"a\u202eb"}"#.to_string(),
            r#"{"name":"bad","hosts":["x.com"]}"#.to_string(),
            good.to_string(),
            r#"{"name":"maps","hosts":["evil.example"],"why":"Maps"}"#.to_string(),
        ];
        fs::write(&path, format!(r#"{{"requests":[{}]}}"#, entries.join(","))).unwrap();
        let waiting = load(&path).unwrap();
        assert_eq!(waiting.requests, vec![KeyRequest::new("maps", &strings(&["x.com"]), &[], "Maps", None).unwrap()]);
        assert_eq!(waiting.ignored, 5, "broken entries, one without a why, and the second maps are left out");

        let many: Vec<String> = (0..MAX_REQUESTS + 2).map(|i| format!(r#"{{"name":"k{i}","hosts":["x.com"],"why":"x"}}"#)).collect();
        fs::write(&path, format!(r#"{{"requests":[{}]}}"#, many.join(","))).unwrap();
        assert_eq!(load(&path).unwrap().requests.len(), MAX_REQUESTS);

        fs::write(&path, "not json").unwrap();
        let err = format!("{:#}", load(&path).unwrap_err());
        assert!(err.contains("is broken"), "{err}");
    }

    #[test]
    fn a_new_request_replaces_the_old_one_for_that_key() {
        let first = with_request(&[], wanted("maps"));
        let moved = KeyRequest::new("maps", &strings(&["other.example"]), &[], "Maps", None).unwrap();
        let second = with_request(&first, moved.clone());
        assert_eq!(second, vec![moved]);
        assert_eq!(first.len(), 1, "with_request must not change its input");
    }

    #[test]
    fn request_needs_no_terminal_and_never_touches_the_vault() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(REQUESTS_FILE);
        let store = MemoryStore::new(VaultData::default());
        let log = MemoryLog::new();
        let reply = request(&store, &*log, &Registry::default(), &path, wanted("maps")).unwrap();
        assert_eq!((reply.requested.as_str(), reply.why.as_str()), ("maps", "Geocode addresses"));
        assert!(reply.next.contains("tb self vault setup"), "{}", reply.next);
        assert!(store.changes.borrow().is_empty());
        assert_eq!(load(&path).unwrap().requests, vec![wanted("maps")]);
        assert!(matches!(&log.0.borrow()[0], Event::Requested { key, why, .. } if key == "maps" && why == "Geocode addresses"));
    }

    #[test]
    fn request_refuses_keys_already_in_the_vault_and_too_many_requests() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(REQUESTS_FILE);
        let entry = SecretEntry {
            value: SecretValue::new("fake_token_abcdefgh".into()).unwrap(),
            hosts: strings(&["api.example.com"]),
            query_params: vec![],
            commands: std::collections::BTreeMap::default(),
        };
        let store = MemoryStore::new(VaultData::default().with_secret("maps", entry));
        let none = Registry::default();
        let err = request(&store, &*MemoryLog::new(), &none, &path, wanted("maps")).unwrap_err().to_string();
        assert!(err.contains("already in the vault"), "{err}");

        for i in 0..MAX_REQUESTS {
            request(&store, &*MemoryLog::new(), &none, &path, wanted(&format!("key{i}"))).unwrap();
        }
        let err = request(&store, &*MemoryLog::new(), &none, &path, wanted("one-more")).unwrap_err().to_string();
        assert!(err.contains("already waiting"), "{err}");
        assert!(request(&store, &*MemoryLog::new(), &none, &path, wanted("key0")).is_ok(), "replacing still works");
    }
}
