//! Placeholder handling: swapping `{{vault:name}}` for real values on the way
//! out, and scrubbing real values from responses on the way back.

use anyhow::{Result, anyhow, bail, ensure};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use url::{Host, Url};

use super::{SecretEntry, VaultData};
use crate::manifest::is_valid_name;

const PREFIX: &str = "{{vault:";
const SUFFIX: &str = "}}";

pub fn placeholder(name: &str) -> String {
    format!("{PREFIX}{name}{SUFFIX}")
}

pub fn mentions_vault(text: &str) -> bool {
    text.contains(PREFIX)
}

/// Placeholders are only honoured in header values; anywhere else is an error.
pub fn ensure_absent(location: &str, text: &str) -> Result<()> {
    ensure!(
        !mentions_vault(text),
        "vault placeholders are only allowed in header values, found one in the {location}"
    );
    Ok(())
}

/// Splits `text` into literal pieces and placeholder names, in order.
fn parse(text: &str) -> Result<Vec<Piece<'_>>> {
    let mut pieces = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(PREFIX) {
        let after = &rest[start + PREFIX.len()..];
        let end = after
            .find(SUFFIX)
            .ok_or_else(|| anyhow!("unterminated vault placeholder in {text:?}"))?;
        let name = &after[..end];
        ensure!(is_valid_name(name), "invalid vault secret name {name:?}");
        pieces.push(Piece::Literal(&rest[..start]));
        pieces.push(Piece::Secret(name));
        rest = &after[end + SUFFIX.len()..];
    }
    pieces.push(Piece::Literal(rest));
    Ok(pieces)
}

enum Piece<'a> {
    Literal(&'a str),
    Secret(&'a str),
}

/// Replaces placeholders in header values after checking every rule.
pub fn inject_headers(
    headers: &[(String, String)],
    url: &Url,
    vault: &VaultData,
    declared: &[String],
) -> Result<Vec<(String, String)>> {
    headers
        .iter()
        .map(|(name, value)| {
            ensure_absent("header name", name)?;
            Ok((name.clone(), inject_value(value, url, vault, declared)?))
        })
        .collect()
}

fn inject_value(value: &str, url: &Url, vault: &VaultData, declared: &[String]) -> Result<String> {
    parse(value)?
        .into_iter()
        .map(|piece| match piece {
            Piece::Literal(text) => Ok(text.to_string()),
            Piece::Secret(name) => {
                authorize(name, url, vault, declared).map(|e| e.value.expose().to_string())
            }
        })
        .collect()
}

fn authorize<'v>(
    name: &str,
    url: &Url,
    vault: &'v VaultData,
    declared: &[String],
) -> Result<&'v SecretEntry> {
    ensure!(
        declared.iter().any(|d| d == name),
        "secret {name:?} is not listed in this command's permissions.vault"
    );
    let entry = vault.get(name).ok_or_else(|| {
        anyhow!(
            "no secret named {name:?} in the vault. Ask the user to run `tb self vault add {name} --host <host>` in their own terminal"
        )
    })?;
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    let secure = url.scheme() == "https" || (url.scheme() == "http" && is_loopback(url));
    ensure!(
        secure,
        "secret {name:?} can only be sent over https (plain http is allowed for localhost only)"
    );
    if !entry.hosts.contains(&host) {
        bail!(
            "secret {name:?} may only be sent to {:?}, not {host:?}",
            entry.hosts
        );
    }
    Ok(entry)
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// Replaces any known secret value (and common encodings of it) in text.
#[derive(Debug, Default)]
pub struct Redactor {
    needles: Vec<(String, String)>,
}

impl Redactor {
    pub fn new(vault: &VaultData) -> Self {
        let mut needles: Vec<(String, String)> = vault
            .secrets
            .iter()
            .flat_map(|(name, entry)| {
                let label = format!("[REDACTED:{name}]");
                encodings(entry.value.expose())
                    .into_iter()
                    .map(move |needle| (needle, label.clone()))
            })
            .collect();
        // Longest first, so a secret that contains another is replaced whole.
        needles.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(&b.0)));
        needles.dedup_by(|a, b| a.0 == b.0);
        Self { needles }
    }

    pub fn redact(&self, text: &str) -> String {
        self.needles
            .iter()
            .fold(text.to_string(), |acc, (needle, label)| acc.replace(needle, label))
    }
}

fn encodings(secret: &str) -> Vec<String> {
    let percent: String = url::form_urlencoded::byte_serialize(secret.as_bytes()).collect();
    let mut all = vec![
        secret.to_string(),
        STANDARD.encode(secret),
        URL_SAFE_NO_PAD.encode(secret),
        percent,
    ];
    all.sort();
    all.dedup();
    all
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{SecretEntry, SecretValue};

    const TOKEN: &str = "fake_github_token_123";

    fn vault() -> VaultData {
        VaultData::default().with_secret(
            "github",
            SecretEntry {
                value: SecretValue::new(TOKEN.to_string()).unwrap(),
                hosts: vec!["api.github.com".to_string(), "localhost".to_string()],
            },
        )
    }

    fn declared() -> Vec<String> {
        vec!["github".to_string()]
    }

    fn inject(url: &str) -> Result<Vec<(String, String)>> {
        let headers = vec![(
            "Authorization".to_string(),
            format!("Bearer {}", placeholder("github")),
        )];
        inject_headers(&headers, &Url::parse(url).unwrap(), &vault(), &declared())
    }

    #[test]
    fn injects_into_allowed_host() {
        let headers = inject("https://api.github.com/user").unwrap();
        assert_eq!(headers[0].1, format!("Bearer {TOKEN}"));
    }

    #[test]
    fn host_match_is_case_insensitive() {
        assert!(inject("https://API.GitHub.com/user").is_ok());
    }

    #[test]
    fn refuses_other_hosts() {
        let err = inject("https://evil.example/steal").unwrap_err().to_string();
        assert!(err.contains("may only be sent to"));
        assert!(!err.contains(TOKEN));
    }

    #[test]
    fn refuses_userinfo_trick() {
        assert!(inject("https://api.github.com@evil.example/").is_err());
    }

    #[test]
    fn refuses_subdomain_lookalike() {
        assert!(inject("https://api.github.com.evil.example/").is_err());
    }

    #[test]
    fn refuses_plain_http_except_loopback() {
        assert!(inject("http://api.github.com/user").is_err());
        assert!(inject("http://localhost:8080/echo").is_ok());
    }

    #[test]
    fn refuses_undeclared_and_unknown_secrets() {
        let url = Url::parse("https://api.github.com/").unwrap();
        let headers = vec![("X".to_string(), placeholder("github"))];
        let err = inject_headers(&headers, &url, &vault(), &[]).unwrap_err();
        assert!(err.to_string().contains("permissions.vault"));

        let headers = vec![("X".to_string(), placeholder("stripe"))];
        let declared = vec!["stripe".to_string()];
        let err = inject_headers(&headers, &url, &vault(), &declared).unwrap_err();
        assert!(err.to_string().contains("tb self vault add stripe"));
    }

    #[test]
    fn rejects_malformed_placeholders() {
        let url = Url::parse("https://api.github.com/").unwrap();
        for bad in ["{{vault:github", "{{vault:Bad Name}}"] {
            let headers = vec![("X".to_string(), bad.to_string())];
            assert!(inject_headers(&headers, &url, &vault(), &declared()).is_err());
        }
    }

    #[test]
    fn rejects_placeholder_in_header_name() {
        let url = Url::parse("https://api.github.com/").unwrap();
        let headers = vec![(placeholder("github"), "x".to_string())];
        assert!(inject_headers(&headers, &url, &vault(), &declared()).is_err());
    }

    #[test]
    fn ensure_absent_flags_placeholders() {
        assert!(ensure_absent("url", "https://x/?k={{vault:github}}").is_err());
        assert!(ensure_absent("url", "https://x/").is_ok());
    }

    #[test]
    fn redacts_raw_and_encoded_values() {
        let redactor = Redactor::new(&vault());
        let b64 = STANDARD.encode(TOKEN);
        let text = format!("echo: {TOKEN} and {b64}");
        let clean = redactor.redact(&text);
        assert!(!clean.contains(TOKEN));
        assert!(!clean.contains(&b64));
        assert_eq!(clean.matches("[REDACTED:github]").count(), 2);
    }

    #[test]
    fn empty_redactor_changes_nothing() {
        assert_eq!(Redactor::default().redact("hello"), "hello");
    }
}
