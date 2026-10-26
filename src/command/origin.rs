use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::command::registry::{MANIFEST_FILE, SCRIPT_FILE};
use crate::install::source::{self, Source};
use crate::vault;
use crate::vault::approval::fingerprint;

pub const CREATED_FILE: &str = ".created.json";
pub const MAX_RECORD_BYTES: u64 = 64 << 10;
const MAX_COMMAND_FILE_BYTES: u64 = 20 << 20;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Created {
    pub time: String,
    pub by: Vec<String>,
    pub terminal: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Origin {
    Installed {
        #[serde(flatten)]
        source: Source,
        edited: Option<bool>,
    },
    Created(Created),
    Unknown,
    Unreadable {
        problem: String,
    },
}

pub fn origin(command_dir: &Path) -> Origin {
    let found = source::read(command_dir).and_then(|installed| match installed {
        Some(source) => Ok(Origin::Installed { edited: edited(&source, command_dir), source }),
        None => Ok(read_created(command_dir)?.map_or(Origin::Unknown, Origin::Created)),
    });
    found.unwrap_or_else(|err| Origin::Unreadable { problem: format!("{err:#}") })
}

fn edited(source: &Source, command_dir: &Path) -> Option<bool> {
    let installed = source.fingerprint.as_deref()?;
    Some(files_fingerprint(command_dir).ok().as_deref() != Some(installed))
}

pub fn files_fingerprint(command_dir: &Path) -> Result<String> {
    let read = |file| {
        read_plain(&command_dir.join(file), MAX_COMMAND_FILE_BYTES)?
            .with_context(|| format!("{} has no {file}", command_dir.display()))
    };
    Ok(fingerprint(&read(MANIFEST_FILE)?, &read(SCRIPT_FILE)?))
}

pub fn record_created(command_dir: &Path) -> Result<()> {
    let created = Created {
        time: chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false),
        by: vault::ancestors(),
        terminal: vault::log::has_terminal(),
    };
    let path = command_dir.join(CREATED_FILE);
    std::fs::write(&path, serde_json::to_string_pretty(&created)? + "\n")
        .with_context(|| format!("could not write {}", path.display()))
}

pub fn read_created(command_dir: &Path) -> Result<Option<Created>> {
    let path = command_dir.join(CREATED_FILE);
    read_plain(&path, MAX_RECORD_BYTES)?
        .map(|raw| serde_json::from_str(&raw).with_context(|| format!("invalid {}", path.display())))
        .transpose()
}

pub fn read_plain(path: &Path, max_bytes: u64) -> Result<Option<String>> {
    let opened = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path);
    let file = match opened {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).with_context(|| format!("could not open {}", path.display())),
    };
    ensure!(file.metadata()?.is_file(), "{} is not a plain file", path.display());
    let mut text = String::new();
    file.take(max_bytes + 1)
        .read_to_string(&mut text)
        .with_context(|| format!("could not read {}", path.display()))?;
    ensure!(text.len() as u64 <= max_bytes, "{} is larger than {max_bytes} bytes", path.display());
    Ok(Some(text))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::process::Command;

    use super::*;

    fn command_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(MANIFEST_FILE), "{}").unwrap();
        fs::write(dir.path().join(SCRIPT_FILE), "return function() end").unwrap();
        dir
    }

    fn installed_from(dir: &Path, fingerprint: Option<String>) -> Source {
        let source = Source {
            url: "https://github.com/acme/tools.git".into(),
            git_ref: None,
            commit: "abc123".into(),
            market: Some("acme".into()),
            fingerprint,
        };
        source::write(dir, &source).unwrap();
        source
    }

    #[test]
    fn a_folder_without_records_is_unknown() {
        assert_eq!(origin(command_dir().path()), Origin::Unknown);
    }

    #[test]
    fn created_commands_say_who_made_them() {
        let dir = command_dir();
        record_created(dir.path()).unwrap();
        let Origin::Created(created) = origin(dir.path()) else { panic!("not created") };
        assert!(!created.by.is_empty(), "the test runner has a parent");
        assert!(created.time.contains('T'), "{}", created.time);
    }

    #[test]
    fn installed_commands_notice_local_edits() {
        let dir = command_dir();
        let source = installed_from(dir.path(), Some(files_fingerprint(dir.path()).unwrap()));
        assert_eq!(origin(dir.path()), Origin::Installed { source: source.clone(), edited: Some(false) });

        fs::write(dir.path().join(SCRIPT_FILE), "return function() return 1 end").unwrap();
        assert_eq!(origin(dir.path()), Origin::Installed { source: source.clone(), edited: Some(true) });

        fs::remove_file(dir.path().join(SCRIPT_FILE)).unwrap();
        assert_eq!(origin(dir.path()), Origin::Installed { source, edited: Some(true) });
    }

    #[test]
    fn installs_from_older_versions_cannot_tell_edits() {
        let dir = command_dir();
        let source = installed_from(dir.path(), None);
        assert_eq!(origin(dir.path()), Origin::Installed { source, edited: None });
    }

    #[test]
    fn origin_serializes_flat_with_a_kind() {
        let dir = command_dir();
        installed_from(dir.path(), None);
        let json = serde_json::to_value(origin(dir.path())).unwrap();
        assert_eq!(json["kind"], "installed");
        assert_eq!(json["market"], "acme");
        assert_eq!(json["edited"], serde_json::Value::Null);
        assert_eq!(serde_json::to_value(Origin::Unknown).unwrap(), serde_json::json!({ "kind": "unknown" }));
    }

    #[test]
    fn broken_records_are_reported_not_trusted() {
        let dir = command_dir();
        fs::write(dir.path().join(CREATED_FILE), "{\"time\": 1}").unwrap();
        let Origin::Unreadable { problem } = origin(dir.path()) else { panic!("not unreadable") };
        assert!(problem.contains(CREATED_FILE), "{problem}");
    }

    #[test]
    fn a_fifo_or_a_huge_record_cannot_hang_or_flood_a_read() {
        let dir = command_dir();
        let fifo = dir.path().join(source::SOURCE_FILE);
        assert!(Command::new("mkfifo").arg(&fifo).status().unwrap().success());
        let Origin::Unreadable { problem } = origin(dir.path()) else { panic!("not unreadable") };
        assert!(problem.contains("not a plain file"), "{problem}");

        fs::remove_file(&fifo).unwrap();
        fs::write(dir.path().join(CREATED_FILE), " ".repeat(usize::try_from(MAX_RECORD_BYTES).unwrap() + 1)).unwrap();
        let Origin::Unreadable { problem } = origin(dir.path()) else { panic!("not unreadable") };
        assert!(problem.contains("larger than"), "{problem}");
    }

    #[test]
    fn symlinked_records_are_refused() {
        let dir = command_dir();
        std::os::unix::fs::symlink("/dev/zero", dir.path().join(CREATED_FILE)).unwrap();
        assert!(matches!(origin(dir.path()), Origin::Unreadable { .. }));
    }
}
