//! Tells a human at the terminal when a newer release is out.
//! Checks GitHub at most once a day, and never when stderr is not a terminal,
//! so agents and pipes never see the notice or wait for the request.

use std::fmt;
use std::fs;
use std::io::IsTerminal;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::paths;

/// Set to anything to turn the check off.
const OPT_OUT_ENV: &str = "TOOLBOX_NO_UPDATE_CHECK";
const LATEST_RELEASE_URL: &str =
    "https://api.github.com/repos/WilliamThogersen/toolbox/releases/latest";
const CACHE_FILE: &str = "update-check.json";
const CHECK_EVERY: Duration = Duration::from_secs(24 * 60 * 60);
const TIMEOUT: Duration = Duration::from_secs(2);
const MAX_BODY_BYTES: u64 = 256 * 1024;

/// Prints a one-line notice to stderr when a newer release is out. Never fails the run.
pub fn notify() {
    if !std::io::stderr().is_terminal() || std::env::var_os(OPT_OUT_ENV).is_some() {
        return;
    }
    let Ok(home) = paths::toolbox_home() else {
        return;
    };
    let current = env!("CARGO_PKG_VERSION");
    if let Some(latest) = newer_release(&home.join(CACHE_FILE), unix_now(), current, fetch_latest) {
        eprintln!(
            "note: toolbox {latest} is out, you have {current}. Update with: brew upgrade toolbox"
        );
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Cache {
    /// Unix seconds of the last check.
    checked_at: u64,
    latest: Option<String>,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Version([u64; 3]);

impl Version {
    /// Accepts `1.2.3` or `v1.2.3`. Anything else (pre-releases, junk) is `None`.
    fn parse(text: &str) -> Option<Self> {
        let mut parts = text.strip_prefix('v').unwrap_or(text).split('.');
        let mut next = || parts.next()?.parse::<u64>().ok();
        let version = [next()?, next()?, next()?];
        parts.next().is_none().then_some(Self(version))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [major, minor, patch] = self.0;
        write!(f, "{major}.{minor}.{patch}")
    }
}

/// The release to tell the user about, if it is newer than `current`.
/// Refreshes the cached answer with `fetch` once it is a day old.
fn newer_release(
    cache_path: &Path,
    now: u64,
    current: &str,
    fetch: impl FnOnce() -> Result<String>,
) -> Option<Version> {
    let cache = read_cache(cache_path);
    // A timestamp in the future is as good as none.
    let stale = now
        .checked_sub(cache.checked_at)
        .is_none_or(|age| age >= CHECK_EVERY.as_secs());
    let latest = if stale {
        // Keep the last answer when offline, and still wait a day before asking again.
        let latest = fetch().ok().or(cache.latest);
        // Ignored on purpose: an unwritable cache only means asking again on the next run.
        let _ = write_cache(
            cache_path,
            &Cache {
                checked_at: now,
                latest: latest.clone(),
            },
        );
        latest
    } else {
        cache.latest
    };
    let latest = Version::parse(&latest?)?;
    (latest > Version::parse(current)?).then_some(latest)
}

fn read_cache(path: &Path) -> Cache {
    fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

fn write_cache(path: &Path, cache: &Cache) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    fs::write(path, serde_json::to_string(cache)?)?;
    Ok(())
}

fn fetch_latest() -> Result<String> {
    #[derive(Deserialize)]
    struct Release {
        tag_name: String,
    }

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(TIMEOUT))
        .build()
        .into();
    let body = agent
        .get(LATEST_RELEASE_URL)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", concat!("toolbox/", env!("CARGO_PKG_VERSION")))
        .call()?
        .body_mut()
        .with_config()
        .limit(MAX_BODY_BYTES)
        .read_to_string()?;
    Ok(serde_json::from_str::<Release>(&body)?.tag_name)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use anyhow::anyhow;

    use super::*;

    const NOW: u64 = 1_800_000_000;
    const DAY: u64 = 24 * 60 * 60;

    fn write_cache(path: &Path, checked_at: u64, latest: &str) {
        let cache = Cache {
            checked_at,
            latest: Some(latest.to_string()),
        };
        fs::write(path, serde_json::to_string(&cache).unwrap()).unwrap();
    }

    fn read_cache(path: &Path) -> Cache {
        serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
    }

    fn no_fetch() -> Result<String> {
        panic!("fetched although the cache is fresh")
    }

    #[test]
    fn parses_plain_and_v_prefixed_versions() {
        assert_eq!(Version::parse("0.2.0"), Some(Version([0, 2, 0])));
        assert_eq!(Version::parse("v1.10.3"), Some(Version([1, 10, 3])));
        assert_eq!(Version::parse("v1.10.3").unwrap().to_string(), "1.10.3");
    }

    #[test]
    fn rejects_anything_that_is_not_three_numbers() {
        for text in [
            "",
            "1.2",
            "1.2.3.4",
            "1.2.3-rc1",
            "v",
            "a.b.c",
            "\x1b[31m1.2.3",
        ] {
            assert_eq!(Version::parse(text), None, "{text:?}");
        }
    }

    #[test]
    fn compares_numerically() {
        assert!(Version::parse("0.10.0") > Version::parse("0.9.9"));
    }

    #[test]
    fn fresh_cache_answers_without_fetching() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("update-check.json");
        write_cache(&path, NOW - DAY + 60, "v0.2.0");

        assert_eq!(
            newer_release(&path, NOW, "0.1.0", no_fetch),
            Some(Version([0, 2, 0]))
        );
    }

    #[test]
    fn missing_cache_fetches_and_saves() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("home").join("update-check.json");

        let found = newer_release(&path, NOW, "0.1.0", || Ok("v0.2.0".into()));

        assert_eq!(found, Some(Version([0, 2, 0])));
        let cache = read_cache(&path);
        assert_eq!(cache.checked_at, NOW);
        assert_eq!(cache.latest.as_deref(), Some("v0.2.0"));
    }

    #[test]
    fn day_old_cache_fetches_again() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("update-check.json");
        write_cache(&path, NOW - DAY, "v0.2.0");

        assert_eq!(
            newer_release(&path, NOW, "0.1.0", || Ok("v0.3.0".into())),
            Some(Version([0, 3, 0]))
        );
        assert_eq!(read_cache(&path).latest.as_deref(), Some("v0.3.0"));
    }

    #[test]
    fn failed_fetch_keeps_last_answer_and_waits_a_day() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("update-check.json");
        write_cache(&path, NOW - DAY, "v0.2.0");

        let found = newer_release(&path, NOW, "0.1.0", || Err(anyhow!("offline")));

        assert_eq!(found, Some(Version([0, 2, 0])));
        assert_eq!(read_cache(&path).checked_at, NOW);
    }

    #[test]
    fn corrupt_or_future_cache_counts_as_stale() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("update-check.json");
        fs::write(&path, "not json").unwrap();
        assert_eq!(
            newer_release(&path, NOW, "0.1.0", || Ok("v0.2.0".into())),
            Some(Version([0, 2, 0]))
        );

        write_cache(&path, u64::MAX, "v0.2.0");
        assert_eq!(
            newer_release(&path, NOW, "0.1.0", || Ok("v0.4.0".into())),
            Some(Version([0, 4, 0]))
        );
    }

    #[test]
    fn same_older_or_junk_release_is_not_news() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("update-check.json");
        for latest in ["v0.1.0", "v0.0.9", "v0.2.0-rc1", "\x1b]8;;evil"] {
            write_cache(&path, NOW, latest);
            assert_eq!(
                newer_release(&path, NOW, "0.1.0", no_fetch),
                None,
                "{latest:?}"
            );
        }
    }
}
