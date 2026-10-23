//! The key log: every time a key is added, allowed, revoked, removed, used or
//! refused, with when, by which command and from which programs. Never a value.
//!
//! Each entry goes to `$TOOLBOX_HOME/vault-log.jsonl` for `tb self vault log`, and
//! to the system log. An agent with the user's shell can edit the file, but not the
//! system log, which also records the path of the program that wrote each entry.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;

use super::store::TEST_VAULT_ENV;
use crate::paths;

pub const LOG_FILE: &str = "vault-log.jsonl";
const OLD_LOG_FILE: &str = "vault-log.1.jsonl";
/// The file starts over past this size; the previous one is kept as `vault-log.1.jsonl`.
const ROTATE_AT: u64 = 5 * 1024 * 1024;
/// Prefix of every system log message, to find them with `log show`.
const SYSTEM_PREFIX: &str = "vault ";

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Added { key: String, hosts: Vec<String>, query_params: Vec<String>, new_value: bool },
    Allowed { key: String, command: String },
    Declined { key: String, command: String },
    Revoked { key: String, command: String },
    Removed { key: String },
    Used { keys: Vec<String>, command: String, request: Request, outcome: Outcome },
    Refused { keys: Vec<String>, command: String, request: Request, reason: String },
}

/// Where a request carrying a key went. The query string is left out: it may hold the key.
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
    /// The programs that started this `tb`, nearest first, as paths like `/bin/zsh`.
    /// Paths, not names: Claude Code's process is named after its version.
    by: Vec<String>,
    /// Whether a person's terminal was attached.
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
    /// Also write to the system log. Off for the plain-text test vault.
    pub system: bool,
}

/// Recording never stops a command: the system log is the copy that counts, and a
/// file an agent made unwritable must not turn into a way to break commands.
impl AuditLog for FileLog {
    fn record(&self, event: Event) {
        let entry = Entry {
            time: chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false),
            event: &event,
            by: process::ancestors(),
            terminal: process::has_terminal(),
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
    // One write per entry, so entries from commands running side by side don't mix.
    file.write_all(format!("{line}\n").as_bytes())?;
    Ok(())
}

fn system_log(line: &str) {
    let Ok(message) = std::ffi::CString::new(format!("{SYSTEM_PREFIX}{line}")) else { return };
    // SAFETY: a literal format with one %s, given one NUL-terminated string.
    unsafe { libc::syslog(libc::LOG_NOTICE, c"%s".as_ptr(), message.as_ptr()) };
}

/// What `tb self vault log` shows: entries from the file (and the one before it),
/// newest first, optionally only for one key or one command.
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

/// Who ran `tb`: the chain of parent programs, and whether a terminal was attached.
mod process {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    /// Enough to see past shells and wrappers to the app that started them.
    #[cfg(target_os = "macos")]
    const MAX_ANCESTORS: usize = 8;

    pub fn has_terminal() -> bool {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOCTTY)
            .open("/dev/tty")
            .is_ok()
    }

    #[cfg(target_os = "macos")]
    pub fn ancestors() -> Vec<String> {
        let home = dirs::home_dir().map(|home| home.display().to_string());
        // SAFETY: getppid takes no arguments and can't fail.
        let mut pid = unsafe { libc::getppid() };
        let mut found = Vec::new();
        while pid > 1 && found.len() < MAX_ANCESTORS {
            let Some((program, parent)) = info(pid) else { break };
            let shown = match &home {
                Some(home) if program.starts_with(&format!("{home}/")) => format!("~{}", &program[home.len()..]),
                _ => program,
            };
            found.push(shown);
            pid = parent;
        }
        found
    }

    /// The program's path (its name if the path can't be read) and its parent.
    #[cfg(target_os = "macos")]
    fn info(pid: libc::pid_t) -> Option<(String, libc::pid_t)> {
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        // SAFETY: `info` is a proc_bsdinfo and `size` is its size, as PROC_PIDTBSDINFO expects.
        let got = unsafe {
            libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size)
        };
        if got != size {
            return None;
        }
        let mut path = [0 as libc::c_char; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        // SAFETY: `path` is a buffer of the size passed in.
        let len = unsafe { libc::proc_pidpath(pid, path.as_mut_ptr().cast(), path.len() as u32) };
        let program = if len > 0 { text(&path) } else { text(&info.pbi_comm) };
        Some((program, info.pbi_ppid as libc::pid_t))
    }

    #[cfg(target_os = "macos")]
    fn text(chars: &[libc::c_char]) -> String {
        let bytes: Vec<u8> = chars.iter().take_while(|c| **c != 0).map(|c| *c as u8).collect();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// Only macOS has a vault, so only it records this.
    #[cfg(not(target_os = "macos"))]
    pub fn ancestors() -> Vec<String> {
        Vec::new()
    }
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
        fs::write(&path, "x".repeat(ROTATE_AT as usize + 1)).unwrap();
        let log = FileLog { path: path.clone(), system: false };
        log.record(Event::Removed { key: "old".into() });

        assert!(fs::metadata(&path).unwrap().len() < 1000);
        assert!(path.with_file_name(OLD_LOG_FILE).exists());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        // The old file's lines aren't JSON here, so only the new entry reads back.
        assert_eq!(read(&path, &Filter { key: None, command: None, limit: 10 }).unwrap().len(), 1);
    }

    #[test]
    fn a_missing_log_reads_as_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let filter = Filter { key: None, command: None, limit: 10 };
        assert!(read(&tmp.path().join(LOG_FILE), &filter).unwrap().is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn ancestors_name_the_programs_that_started_us() {
        let names = process::ancestors();
        assert!(!names.is_empty(), "the test runner has a parent");
        assert!(names.iter().all(|name| !name.is_empty()));
    }
}
