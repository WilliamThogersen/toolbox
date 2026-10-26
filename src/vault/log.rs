use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;

use super::platform;
use super::store::TEST_VAULT_ENV;
use crate::cli::paths;
use crate::sys;

pub const LOG_FILE: &str = "vault-log.jsonl";
const OLD_LOG_FILE: &str = "vault-log.1.jsonl";
const ROTATE_AT: u64 = 5 * 1024 * 1024;
const SYSTEM_PREFIX: &str = "vault ";

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Requested { key: String, hosts: Vec<String>, query_params: Vec<String>, why: String },
    Added { key: String, hosts: Vec<String>, query_params: Vec<String>, new_value: bool },
    Allowed { key: String, command: String },
    Declined { key: String, command: String },
    Revoked { key: String, command: String },
    Removed { key: String },
    Used { keys: Vec<String>, command: String, request: Request, outcome: Outcome },
    Refused { keys: Vec<String>, command: String, request: Request, reason: String },
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Request {
    pub method: String,
    pub host: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Status(u16),
    Failed(String),
}

#[derive(Serialize)]
struct Entry<'a> {
    time: String,
    #[serde(flatten)]
    event: &'a Event,
    by: Vec<String>,
    terminal: bool,
}

pub trait AuditLog {
    fn record(&self, event: Event);
}

impl<T: AuditLog + ?Sized> AuditLog for std::rc::Rc<T> {
    fn record(&self, event: Event) {
        (**self).record(event);
    }
}

pub struct FileLog {
    pub path: PathBuf,
    pub system: bool,
}

impl AuditLog for FileLog {
    fn record(&self, event: Event) {
        let entry = Entry {
            time: chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false),
            event: &event,
            by: platform::ancestors(),
            terminal: has_terminal(),
        };
        let Ok(line) = serde_json::to_string(&entry) else { return };
        if self.system {
            system_log(&line);
        }
        if let Err(err) = append(&self.path, &line) {
            eprintln!("toolbox: could not write the key log: {err:#}");
        }
    }
}

pub fn default_log() -> Result<FileLog> {
    Ok(FileLog {
        path: paths::toolbox_home()?.join(LOG_FILE),
        system: std::env::var_os(TEST_VAULT_ENV).is_none(),
    })
}

fn append(path: &Path, line: &str) -> Result<()> {
    if fs::metadata(path).is_ok_and(|meta| meta.len() > ROTATE_AT) {
        fs::rename(path, path.with_file_name(OLD_LOG_FILE)).context("could not rotate it")?;
    }
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("could not open {}", path.display()))?;
    file.write_all(format!("{line}\n").as_bytes())?;
    Ok(())
}

fn system_log(line: &str) {
    if let Ok(message) = CString::new(format!("{SYSTEM_PREFIX}{line}")) {
        sys::syslog(&message);
    }
}

fn has_terminal() -> bool {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOCTTY)
        .open("/dev/tty")
        .is_ok()
}

pub struct Filter<'a> {
    pub key: Option<&'a str>,
    pub command: Option<&'a str>,
    pub limit: usize,
}

pub fn read(path: &Path, filter: &Filter) -> Result<Vec<Value>> {
    let mut entries = Vec::new();
    for file in [path.with_file_name(OLD_LOG_FILE), path.to_path_buf()] {
        match fs::read_to_string(&file) {
            Ok(text) => entries.extend(text.lines().filter_map(|line| serde_json::from_str::<Value>(line).ok())),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err).with_context(|| format!("could not read {}", file.display())),
        }
    }
    Ok(entries.into_iter().rev().filter(|entry| matches(entry, filter)).take(filter.limit).collect())
}

fn matches(entry: &Value, filter: &Filter) -> bool {
    let key_ok = filter.key.is_none_or(|key| {
        entry["key"] == key || entry["keys"].as_array().is_some_and(|keys| keys.iter().any(|k| k == key))
    });
    let command_ok = filter.command.is_none_or(|command| entry["command"] == command);
    key_ok && command_ok
}

#[cfg(test)]
pub struct MemoryLog(pub std::cell::RefCell<Vec<Event>>);

#[cfg(test)]
impl MemoryLog {
    pub fn new() -> std::rc::Rc<Self> {
        std::rc::Rc::new(Self(std::cell::RefCell::new(Vec::new())))
    }
}

#[cfg(test)]
impl AuditLog for MemoryLog {
    fn record(&self, event: Event) {
        self.0.borrow_mut().push(event);
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn used(key: &str, command: &str) -> Event {
        Event::Used {
            keys: vec![key.into()],
            command: command.into(),
            request: Request { method: "GET".into(), host: "api.github.com".into(), path: "/user".into() },
            outcome: Outcome::Status(200),
        }
    }

    #[test]
    fn entries_are_json_lines_readable_newest_first() {
        let tmp = tempfile::tempdir().unwrap();
        let log = FileLog { path: tmp.path().join(LOG_FILE), system: false };
        log.record(Event::Allowed { key: "github".into(), command: "stars".into() });
        log.record(used("github", "stars"));
        log.record(used("stripe", "pay"));

        let text = fs::read_to_string(&log.path).unwrap();
        assert_eq!(text.lines().count(), 3);
        let all = read(&log.path, &Filter { key: None, command: None, limit: 10 }).unwrap();
        assert_eq!(all[0]["key"], Value::Null);
        assert_eq!(all[0]["keys"][0], "stripe");
        assert_eq!(all[0]["event"], "used");
        assert_eq!(all[0]["request"]["path"], "/user");
        assert_eq!(all[0]["outcome"]["status"], 200);
        assert!(all[0]["time"].as_str().unwrap().len() >= 20);
        assert!(all[0]["by"].is_array() && all[0]["terminal"].is_boolean());

        let github = read(&log.path, &Filter { key: Some("github"), command: None, limit: 10 }).unwrap();
        assert_eq!(github.iter().map(|e| e["event"].clone()).collect::<Vec<_>>(), ["used", "allowed"]);
        let one = read(&log.path, &Filter { key: None, command: Some("stars"), limit: 1 }).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0]["event"], "used");
    }

    #[test]
    fn the_file_is_private_and_rotates() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(LOG_FILE);
        fs::write(&path, "x".repeat(usize::try_from(ROTATE_AT).unwrap() + 1)).unwrap();
        let log = FileLog { path: path.clone(), system: false };
        log.record(Event::Removed { key: "old".into() });

        assert!(fs::metadata(&path).unwrap().len() < 1000);
        assert!(path.with_file_name(OLD_LOG_FILE).exists());
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(read(&path, &Filter { key: None, command: None, limit: 10 }).unwrap().len(), 1);
    }

    #[test]
    fn a_missing_log_reads_as_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let filter = Filter { key: None, command: None, limit: 10 };
        assert!(read(&tmp.path().join(LOG_FILE), &filter).unwrap().is_empty());
    }
}
