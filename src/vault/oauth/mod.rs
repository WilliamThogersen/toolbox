mod cache;
#[cfg(test)]
mod fake;
pub mod login;
mod token;

use std::collections::BTreeMap;

use anyhow::{Result, anyhow, ensure};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use url::{Host, Url};

pub use cache::{Cached, TokenCache};

use super::log::{AuditLog, Event, Outcome};
use super::{SecretEntry, SecretValue};

const MAX_CLIENT_ID_LEN: usize = 256;
const MAX_SCOPE_LEN: usize = 256;
const DEFAULT_LIFETIME_SECS: u64 = 3600;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuth {
    pub auth_url: String,
    pub token_url: String,
    pub client_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<SecretValue>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub auth_params: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    pub cache_key: SecretValue,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct OAuthSummary {
    pub auth_url: String,
    pub token_url: String,
    pub client_id: String,
    pub scopes: Vec<String>,
}

impl OAuth {
    pub fn summary(&self) -> OAuthSummary {
        OAuthSummary {
            auth_url: self.auth_url.clone(),
            token_url: self.token_url.clone(),
            client_id: self.client_id.clone(),
            scopes: self.scopes.clone(),
        }
    }

    pub fn token_host(&self) -> String {
        host_of(&self.token_url)
    }

    pub fn auth_host(&self) -> String {
        host_of(&self.auth_url)
    }
}

fn host_of(url: &str) -> String {
    Url::parse(url).ok().and_then(|url| url.host_str().map(str::to_string)).unwrap_or_default()
}

pub fn normalize_endpoint(flag: &str, raw: &str) -> Result<String> {
    let invalid = |why: &str| anyhow!("{flag} {raw:?} {why}");
    let url = Url::parse(raw.trim()).map_err(|_| invalid("is not a URL"))?;
    ensure!(url.username().is_empty() && url.password().is_none(), invalid("must not hold a user or password"));
    ensure!(url.fragment().is_none(), invalid("must not have a #fragment"));
    let local = match url.host() {
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    };
    let secure = url.scheme() == "https" || (url.scheme() == "http" && local && url.port().is_some());
    ensure!(secure, invalid("must use https (plain http only to 127.0.0.1 or [::1] with a port)"));
    Ok(url.to_string())
}

pub fn normalize_client_id(raw: &str) -> Result<String> {
    let id = raw.trim();
    ensure!(
        !id.is_empty() && id.len() <= MAX_CLIENT_ID_LEN && id.chars().all(|c| c.is_ascii_graphic()),
        "{raw:?} is not a client id: use the one the provider shows, without spaces"
    );
    Ok(id.to_string())
}

pub fn normalize_scope(raw: &str) -> Result<String> {
    let scope = raw.trim();
    ensure!(
        !scope.is_empty() && scope.len() <= MAX_SCOPE_LEN && scope.chars().all(|c| c.is_ascii_graphic()),
        "{raw:?} is not a scope: use one word or URL per --scope"
    );
    Ok(scope.to_string())
}

fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow!("could not get random bytes from the system"))?;
    Ok(bytes)
}

pub fn random_text() -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(random_bytes::<32>()?))
}

pub fn new_cache_key() -> Result<SecretValue> {
    SecretValue::new(random_text()?)
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

pub fn expires_at(lifetime: Option<u64>) -> u64 {
    now().saturating_add(lifetime.unwrap_or(DEFAULT_LIFETIME_SECS))
}

pub struct Minted {
    pub access: SecretValue,
    pub refresh: SecretValue,
}

pub struct Minter<'a> {
    pub cache: &'a TokenCache,
    pub log: &'a dyn AuditLog,
    pub command: &'a str,
}

impl Minter<'_> {
    pub fn access_token(&self, name: &str, entry: &SecretEntry, oauth: &OAuth) -> Result<Minted> {
        if let Some(fresh) = self.cache.read(name, &oauth.cache_key).filter(|c| c.fresh(now())) {
            return Ok(Minted { access: fresh.access, refresh: fresh.refresh });
        }
        let _lock = self.cache.lock(name)?;
        let cached = self.cache.read(name, &oauth.cache_key);
        if let Some(fresh) = cached.as_ref().filter(|c| c.fresh(now())) {
            return Ok(Minted { access: fresh.access.clone(), refresh: fresh.refresh.clone() });
        }
        let refresh = cached.map_or_else(|| entry.value.clone(), |c| c.refresh);
        let reply = token::refresh(oauth, &refresh);
        let outcome = match &reply {
            Ok(tokens) => Outcome::Status(tokens.status),
            Err(err) => Outcome::Failed(format!("{err:#}")),
        };
        self.log.record(Event::Refreshed {
            key: name.to_string(),
            command: self.command.to_string(),
            host: oauth.token_host(),
            outcome,
        });
        let tokens = reply.map_err(|err| {
            anyhow!(
                "could not get a fresh token for {name:?}: {err:#}. If the sign-in expired or was revoked, ask the user to run `tb self vault oauth {name}` in their own terminal"
            )
        })?;
        let fresh = Cached {
            access: tokens.access,
            refresh: tokens.refresh.unwrap_or(refresh),
            expires_at: expires_at(tokens.expires_in),
        };
        if let Err(err) = self.cache.write(name, &oauth.cache_key, &fresh) {
            eprintln!("toolbox: could not keep the new token for {name}, so the next run asks the server again: {err:#}");
        }
        Ok(Minted { access: fresh.access, refresh: fresh.refresh })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::log::MemoryLog;
    use fake::{token_server, tokens};

    fn value(text: &str) -> SecretValue {
        SecretValue::new(text.to_string()).unwrap()
    }

    fn signed_in(token_url: &str) -> SecretEntry {
        let oauth = OAuth {
            auth_url: "https://accounts.example.com/auth".into(),
            token_url: token_url.into(),
            client_id: "fake-client".into(),
            client_secret: Some(value("fake_client_secret_1")),
            scopes: vec![],
            auth_params: BTreeMap::new(),
            port: None,
            cache_key: new_cache_key().unwrap(),
        };
        SecretEntry { oauth: Some(oauth), ..SecretEntry::new(value("fake_refresh_old"), vec!["api.example.com".into()]) }
    }

    fn form(body: &str) -> BTreeMap<String, String> {
        url::form_urlencoded::parse(body.as_bytes()).into_owned().collect()
    }

    #[test]
    fn a_token_is_fetched_once_then_read_from_the_cache() {
        let server = token_server(vec![(200, tokens("fake_access_1", None, Some(3600)))]);
        let entry = signed_in(&server.url);
        let (tmp, log) = (tempfile::tempdir().unwrap(), MemoryLog::new());
        let cache = TokenCache { dir: tmp.path().to_path_buf() };
        let minter = Minter { cache: &cache, log: &*log, command: "mail" };
        let oauth = entry.oauth.as_ref().unwrap();

        let first = minter.access_token("google", &entry, oauth).unwrap();
        assert_eq!((first.access.expose(), first.refresh.expose()), ("fake_access_1", "fake_refresh_old"));
        let sent = form(&server.bodies.recv().unwrap());
        assert_eq!((sent["grant_type"].as_str(), sent["refresh_token"].as_str()), ("refresh_token", "fake_refresh_old"));
        assert_eq!((sent["client_id"].as_str(), sent["client_secret"].as_str()), ("fake-client", "fake_client_secret_1"));

        let second = minter.access_token("google", &entry, oauth).unwrap();
        assert_eq!(second.access.expose(), "fake_access_1", "the second run must not ask the server again");
        let events = log.0.borrow();
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], Event::Refreshed { key, command, host, outcome: Outcome::Status(200) }
            if key == "google" && command == "mail" && host == "127.0.0.1"));
    }

    #[test]
    fn a_new_refresh_token_from_the_server_is_used_next_time() {
        let server = token_server(vec![
            (200, tokens("fake_access_1", Some("fake_refresh_new"), Some(0))),
            (200, tokens("fake_access_2", None, Some(3600))),
        ]);
        let entry = signed_in(&server.url);
        let (tmp, log) = (tempfile::tempdir().unwrap(), MemoryLog::new());
        let cache = TokenCache { dir: tmp.path().to_path_buf() };
        let minter = Minter { cache: &cache, log: &*log, command: "mail" };
        let oauth = entry.oauth.as_ref().unwrap();

        assert_eq!(minter.access_token("google", &entry, oauth).unwrap().refresh.expose(), "fake_refresh_new");
        let later = minter.access_token("google", &entry, oauth).unwrap();
        assert_eq!((later.access.expose(), later.refresh.expose()), ("fake_access_2", "fake_refresh_new"));
        server.bodies.recv().unwrap();
        assert_eq!(form(&server.bodies.recv().unwrap())["refresh_token"], "fake_refresh_new");
    }

    #[test]
    fn a_revoked_sign_in_says_how_to_sign_in_again() {
        let refusal = r#"{"error":"invalid_grant","error_description":"Token has been expired or revoked."}"#;
        let server = token_server(vec![(400, refusal.to_string())]);
        let entry = signed_in(&server.url);
        let (tmp, log) = (tempfile::tempdir().unwrap(), MemoryLog::new());
        let cache = TokenCache { dir: tmp.path().to_path_buf() };
        let minter = Minter { cache: &cache, log: &*log, command: "mail" };
        let err = minter.access_token("google", &entry, entry.oauth.as_ref().unwrap()).err().unwrap().to_string();
        assert!(err.contains("invalid_grant: Token has been expired or revoked."), "{err}");
        assert!(err.contains("tb self vault oauth google"), "{err}");
        assert!(!err.contains("fake_"), "{err}");
        assert!(matches!(&log.0.borrow()[0], Event::Refreshed { outcome: Outcome::Failed(_), .. }));
    }

    #[test]
    fn endpoints_need_https_or_a_local_port() {
        assert_eq!(
            normalize_endpoint("--token-url", " https://oauth2.googleapis.com/token ").unwrap(),
            "https://oauth2.googleapis.com/token"
        );
        assert!(normalize_endpoint("--token-url", "http://127.0.0.1:8080/token").is_ok());
        assert!(normalize_endpoint("--token-url", "http://[::1]:8080/token").is_ok());
        for bad in [
            "http://example.com/token",
            "http://127.0.0.1/token",
            "http://localhost:8080/token",
            "https://user:pw@example.com/token",
            "https://example.com/token#x",
            "example.com/token",
            "ftp://example.com/",
        ] {
            let err = normalize_endpoint("--token-url", bad).unwrap_err().to_string();
            assert!(err.starts_with("--token-url"), "{bad}: {err}");
        }
    }

    #[test]
    fn client_ids_and_scopes_are_single_words() {
        assert_eq!(normalize_client_id(" abc.apps.googleusercontent.com ").unwrap(), "abc.apps.googleusercontent.com");
        assert_eq!(normalize_scope("https://www.googleapis.com/auth/gmail.send").unwrap(), "https://www.googleapis.com/auth/gmail.send");
        for bad in ["", "two words", "tab\there", "ø"] {
            assert!(normalize_client_id(bad).is_err(), "{bad:?}");
            assert!(normalize_scope(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn random_text_is_long_and_different_each_time() {
        let (a, b) = (random_text().unwrap(), random_text().unwrap());
        assert_eq!(a.len(), 43);
        assert_ne!(a, b);
        assert!(new_cache_key().is_ok());
    }
}
