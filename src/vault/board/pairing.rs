use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use url::Url;

use super::Connection;
use crate::vault::store::TEST_VAULT_ENV;

const KEYCHAIN_SERVICE: &str = "wgt-worker";
const BASE_URL_ENV: &str = "WGT_BASE_URL";
const TOKEN_ENV: &str = "WGT_DEVICE_TOKEN";
const CONFIG_ENV: &str = "WGT_WORKER_CONFIG";
const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const SECURITY: &str = "/usr/bin/security";

impl Connection {
    pub fn new(base: &str, token: &str) -> Option<Self> {
        let url = Url::parse(base.trim()).ok()?;
        let loopback = matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "::1"));
        let safe = url.scheme() == "https" || (url.scheme() == "http" && loopback);
        let plain = url.username().is_empty() && url.password().is_none() && url.query().is_none();
        let token = token.trim();
        if !safe || !plain || token.is_empty() || url.host_str().is_none() {
            return None;
        }
        Some(Self {
            base: url.as_str().trim_end_matches('/').to_string(),
            token: token.to_string(),
        })
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    pub(super) fn token(&self) -> &str {
        &self.token
    }
}

pub(super) fn find() -> Option<Connection> {
    let testing = std::env::var_os(TEST_VAULT_ENV).is_some();
    let base = env(BASE_URL_ENV).or_else(|| if testing { None } else { configured_base() })?;
    let base = base.trim_end_matches('/').to_string();
    let token = if testing { env(TOKEN_ENV) } else { keychain_token(&base).or_else(|| env(TOKEN_ENV)) }?;
    Connection::new(&base, &token)
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().map(|value| value.trim().to_string()).filter(|value| !value.is_empty())
}

fn config_path() -> Option<PathBuf> {
    match std::env::var_os(CONFIG_ENV) {
        Some(path) => Some(PathBuf::from(path)),
        None => dirs::home_dir().map(|home| home.join(".config/wgt-worker/config.json")),
    }
}

fn configured_base() -> Option<String> {
    let mut text = String::new();
    std::fs::File::open(config_path()?).ok()?.take(MAX_CONFIG_BYTES).read_to_string(&mut text).ok()?;
    let config: serde_json::Value = serde_json::from_str(&text).ok()?;
    config.get("base_url")?.as_str().map(|url| url.trim().to_string())
}

fn keychain_token(base: &str) -> Option<String> {
    let output = Command::new(SECURITY)
        .args(["find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", base, "-w"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let token = String::from_utf8(output.stdout).ok()?;
    Some(token.trim().to_string()).filter(|token| !token.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_or_loopback_boards_are_accepted() {
        assert!(Connection::new("https://board.example.com/", "t").is_some());
        assert!(Connection::new("http://127.0.0.1:8080", "t").is_some());
        assert!(Connection::new("http://board.example.com", "t").is_none());
        assert!(Connection::new("https://user:pw@board.example.com", "t").is_none());
        assert!(Connection::new("https://board.example.com", " ").is_none());
    }

    #[test]
    fn the_trailing_slash_is_dropped() {
        let connection = Connection::new("https://board.example.com/", "t").unwrap();
        assert_eq!(connection.base(), "https://board.example.com");
    }
}
