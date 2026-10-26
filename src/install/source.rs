use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::command::origin::{MAX_RECORD_BYTES, read_plain};

pub const SOURCE_FILE: &str = ".source.json";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub url: String,
    #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
    pub git_ref: Option<String>,
    pub commit: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub market: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

impl Source {
    pub fn same_repo(&self, url: &str) -> bool {
        repo_key(&self.url) == repo_key(url)
    }
}

pub fn repo_key(url: &str) -> &str {
    let url = url.trim_end_matches('/');
    url.strip_suffix(".git").unwrap_or(url)
}

pub fn read(command_dir: &Path) -> Result<Option<Source>> {
    let path = command_dir.join(SOURCE_FILE);
    read_plain(&path, MAX_RECORD_BYTES)?
        .map(|raw| serde_json::from_str(&raw).with_context(|| format!("invalid {}", path.display())))
        .transpose()
}

pub fn write(command_dir: &Path, source: &Source) -> Result<()> {
    let path = command_dir.join(SOURCE_FILE);
    fs::write(&path, serde_json::to_string_pretty(source)? + "\n")
        .with_context(|| format!("could not write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_missing_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(read(tmp.path()).unwrap(), None);
        let source = Source {
            url: "https://gitlab.com/a/tools.git".into(),
            git_ref: Some("v1.0.0".into()),
            commit: "abc123".into(),
            market: Some("acme".into()),
            fingerprint: Some("f".repeat(64)),
        };
        write(tmp.path(), &source).unwrap();
        assert_eq!(read(tmp.path()).unwrap(), Some(source));
    }

    #[test]
    fn files_from_older_versions_still_load() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join(SOURCE_FILE), r#"{"url": "https://github.com/a/tools.git", "commit": "abc123"}"#).unwrap();
        let source = read(tmp.path()).unwrap().unwrap();
        assert_eq!((source.market, source.fingerprint), (None, None));
    }

    #[test]
    fn same_repo_ignores_git_suffix_and_slash() {
        let source = Source {
            url: "https://github.com/a/tools.git".into(),
            git_ref: None,
            commit: String::new(),
            market: None,
            fingerprint: None,
        };
        assert!(source.same_repo("https://github.com/a/tools"));
        assert!(source.same_repo("https://github.com/a/tools/"));
        assert!(!source.same_repo("https://github.com/a/other"));
    }
}
