//! `.source.json`: where an installed command came from, so `tb self update` can fetch it again.

use std::fs;
use std::io;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub const SOURCE_FILE: &str = ".source.json";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub url: String,
    /// Branch, tag or commit given to `--ref`. `None` follows the repo's default branch.
    #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
    pub git_ref: Option<String>,
    pub commit: String,
}

impl Source {
    /// The same repo, ignoring a trailing `/` or `.git`.
    pub fn same_repo(&self, url: &str) -> bool {
        repo_key(&self.url) == repo_key(url)
    }
}

pub fn repo_key(url: &str) -> &str {
    let url = url.trim_end_matches('/');
    url.strip_suffix(".git").unwrap_or(url)
}

/// `None` means the command was made locally, not installed.
pub fn read(command_dir: &Path) -> Result<Option<Source>> {
    let path = command_dir.join(SOURCE_FILE);
    match fs::read_to_string(&path) {
        Ok(raw) => serde_json::from_str(&raw)
            .map(Some)
            .with_context(|| format!("invalid {}", path.display())),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("could not read {}", path.display())),
    }
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
        };
        write(tmp.path(), &source).unwrap();
        assert_eq!(read(tmp.path()).unwrap(), Some(source));
    }

    #[test]
    fn same_repo_ignores_git_suffix_and_slash() {
        let source = Source {
            url: "https://github.com/a/tools.git".into(),
            git_ref: None,
            commit: String::new(),
        };
        assert!(source.same_repo("https://github.com/a/tools"));
        assert!(source.same_repo("https://github.com/a/tools/"));
        assert!(!source.same_repo("https://github.com/a/other"));
    }
}
