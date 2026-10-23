//! Placeholder handling: swapping `{{vault:name}}` for real values on the way
//! out, and scrubbing real values from responses on the way back.

use std::ops::Range;

use anyhow::{Result, anyhow, bail, ensure};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use url::{Host, Url};

use super::approval::{self, Caller};
use super::{MIN_SECRET_LEN, SecretEntry, VaultData, hosts, unescape};
use crate::manifest::is_valid_name;

const PREFIX: &str = "{{vault:";
const SUFFIX: &str = "}}";
const ENCODING_SEPARATOR: char = '|';

/// How a secret is written into the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// As stored.
    Raw,
    /// Standard base64, for `Authorization: Basic` with a stored `user:password`.
    Base64,
}

impl Encoding {
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "base64" => Ok(Self::Base64),
            other => bail!("unknown vault encoding {other:?}. The only one is \"base64\""),
        }
    }

    fn label(self) -> Option<&'static str> {
        match self {
            Self::Raw => None,
            Self::Base64 => Some("base64"),
        }
    }

    fn apply(self, value: &str) -> String {
        match self {
            Self::Raw => value.to_string(),
            Self::Base64 => STANDARD.encode(value),
        }
    }
}

pub fn placeholder(name: &str, encoding: Encoding) -> String {
    match encoding.label() {
        None => format!("{PREFIX}{name}{SUFFIX}"),
        Some(label) => format!("{PREFIX}{name}{ENCODING_SEPARATOR}{label}{SUFFIX}"),
    }
}

pub fn mentions_vault(text: &str) -> bool {
    text.contains(PREFIX)
}

/// Placeholders are only honoured in header values and `query` parameters; anywhere else is an error.
pub fn ensure_absent(location: &str, text: &str) -> Result<()> {
    ensure!(
        !mentions_vault(text),
        "vault placeholders are only allowed in header values and in `query = {{...}}` parameters, found one in the {location}"
    );
    Ok(())
}

/// The secrets `text` asks for. A malformed placeholder is left out here: filling
/// it in fails later with a clear error.
pub fn secret_names(text: &str) -> Vec<String> {
    parse(text)
        .map(|pieces| {
            pieces
                .into_iter()
                .filter_map(|piece| match piece {
                    Piece::Secret(name, _) => Some(name.to_string()),
                    Piece::Literal(_) => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Splits `text` into literal pieces and placeholders, in order.
fn parse(text: &str) -> Result<Vec<Piece<'_>>> {
    let mut pieces = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(PREFIX) {
        let after = &rest[start + PREFIX.len()..];
        let end = after
            .find(SUFFIX)
            .ok_or_else(|| anyhow!("unterminated vault placeholder in {text:?}"))?;
        let (name, encoding) = match after[..end].split_once(ENCODING_SEPARATOR) {
            Some((name, label)) => (name, Encoding::parse(label)?),
            None => (&after[..end], Encoding::Raw),
        };
        ensure!(is_valid_name(name), "invalid vault secret name {name:?}");
        pieces.push(Piece::Literal(&rest[..start]));
        pieces.push(Piece::Secret(name, encoding));
        rest = &after[end + SUFFIX.len()..];
    }
    pieces.push(Piece::Literal(rest));
    Ok(pieces)
}

enum Piece<'a> {
    Literal(&'a str),
    Secret(&'a str, Encoding),
}

/// Where in the request a placeholder sits.
#[derive(Debug, Clone, Copy)]
enum Place<'a> {
    Header,
    Query(&'a str),
}

/// Fills in the placeholders of one request, after checking every rule.
pub struct Injector<'a> {
    pub vault: &'a VaultData,
    pub caller: &'a Caller,
    pub url: &'a Url,
}

impl<'a> Injector<'a> {
    pub fn headers(&self, headers: &[(String, String)]) -> Result<Vec<(String, String)>> {
        headers
            .iter()
            .map(|(name, value)| {
                ensure_absent("header name", name)?;
                Ok((name.clone(), self.fill(value, Place::Header)?))
            })
            .collect()
    }

    /// `query = {...}` pairs, before they are URL-encoded.
    pub fn query(&self, pairs: &[(String, String)]) -> Result<Vec<(String, String)>> {
        pairs
            .iter()
            .map(|(name, value)| {
                ensure_absent("query parameter name", name)?;
                Ok((name.clone(), self.fill(value, Place::Query(name))?))
            })
            .collect()
    }

    fn fill(&self, text: &str, place: Place) -> Result<String> {
        parse(text)?
            .into_iter()
            .map(|piece| match piece {
                Piece::Literal(text) => Ok(text.to_string()),
                Piece::Secret(name, encoding) => self
                    .authorize(name, place)
                    .map(|entry| encoding.apply(entry.value.expose())),
            })
            .collect()
    }

    /// Mistakes the script can fix come first, so the human is only asked to
    /// approve a command once it does what it should.
    fn authorize(&self, name: &str, place: Place) -> Result<&'a SecretEntry> {
        ensure!(
            self.caller.declared.iter().any(|d| d == name),
            "secret {name:?} is not listed in this command's permissions.vault"
        );
        let entry = self.vault.get(name).ok_or_else(|| {
            anyhow!(
                "no secret named {name:?} in the vault. Ask the user to run `tb self vault add {name} --host <host>` in their own terminal"
            )
        })?;
        let url = self.url;
        let secure = url.scheme() == "https" || (url.scheme() == "http" && is_loopback(url));
        ensure!(
            secure,
            "secret {name:?} can only be sent over https (plain http only to this computer, like 127.0.0.1:8080)"
        );
        check_host(name, entry, url)?;
        check_place(name, entry, place)?;
        approval::check(name, entry, self.caller)?;
        Ok(entry)
    }
}

fn check_host(name: &str, entry: &SecretEntry, url: &Url) -> Result<()> {
    if entry.hosts.iter().any(|rule| hosts::allows(rule, url)) {
        return Ok(());
    }
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    if entry.hosts.iter().any(|rule| *rule == host && hosts::is_local(rule)) {
        let fixed: Vec<String> = entry
            .hosts
            .iter()
            .map(|rule| if *rule == host { local_replacement(rule) } else { rule.clone() })
            .collect();
        bail!(
            "secret {name:?} is bound to {host:?} without a port, and any program on this computer could listen there. Ask the user to run `{}` in their own terminal, then call that address in the URL",
            add_command(name, &fixed, &entry.query_params)
        );
    }
    let target = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    };
    bail!("secret {name:?} may only be sent to {:?}, not {target:?}", entry.hosts)
}

fn check_place(name: &str, entry: &SecretEntry, place: Place) -> Result<()> {
    let Place::Query(param) = place else {
        return Ok(());
    };
    if entry.query_params.iter().any(|allowed| allowed == param) {
        return Ok(());
    }
    // The name comes from the script: only a plain one may go into a command the human is asked to paste.
    if !hosts::is_query_param(param) {
        bail!("secret {name:?} can't be sent in the query parameter {param:?}");
    }
    if entry.query_params.is_empty() {
        let wanted = [param.to_string()];
        bail!(
            "secret {name:?} may only be sent in headers. If the API wants it in the query string, ask the user to run `{}` in their own terminal",
            add_command(name, &entry.hosts, &wanted)
        );
    }
    bail!(
        "secret {name:?} may only be sent in the query parameter(s) {:?}, not {param:?}",
        entry.query_params
    )
}

/// What an old port-less local rule should become: the same IPv4 address, or
/// 127.0.0.1 for names like `localhost` that no longer work.
fn local_replacement(rule: &str) -> String {
    match rule.parse::<std::net::Ipv4Addr>() {
        Ok(ip) if ip.is_loopback() => format!("{rule}:<port>"),
        _ => "127.0.0.1:<port>".to_string(),
    }
}

/// The `vault add` line that sets these rules. An empty value at its prompt keeps the key.
fn add_command(name: &str, hosts: &[String], query_params: &[String]) -> String {
    let query = if query_params.is_empty() {
        String::new()
    } else {
        format!(" --query-param {}", query_params.join(","))
    };
    format!("tb self vault add {name} --host {}{query}", hosts.join(","))
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// How many layers of JSON escapes are undone when looking for a key: JSON in a JSON
/// string in a JSON string is deeper than real responses go.
const ESCAPE_LAYERS: usize = 3;

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
                secret_parts(entry.value.expose())
                    .into_iter()
                    .flat_map(encodings)
                    .map(move |needle| (needle, label.clone()))
            })
            .collect();
        // Longest first, so a secret that contains another is replaced whole.
        needles.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(&b.0)));
        needles.dedup_by(|a, b| a.0 == b.0);
        Self { needles }
    }

    /// Whether `text` holds a secret `redact` would replace.
    pub fn finds(&self, text: &str) -> bool {
        self.needles.iter().any(|(needle, _)| text.contains(needle.as_str()))
    }

    pub fn redact(&self, text: &str) -> String {
        let exact = self
            .needles
            .iter()
            .fold(text.to_string(), |acc, (needle, label)| acc.replace(needle, label));
        self.redact_escaped(exact)
    }

    /// Keys written with JSON escapes, in any text and up to `ESCAPE_LAYERS` deep, are
    /// found in the unescaped text and replaced where they sit in `text`. So neither
    /// `json.decode` nor a script's own unescaping can turn them back into the key.
    fn redact_escaped(&self, text: String) -> String {
        if self.needles.is_empty() || !text.contains('\\') {
            return text;
        }
        let layers = unescape::layers(&text, ESCAPE_LAYERS);
        let hits: Vec<(Range<usize>, &str)> = layers
            .iter()
            .enumerate()
            .flat_map(|(depth, layer)| {
                let below = &layers[..=depth];
                self.matches(&layer.text).map(move |(range, label)| {
                    let range = below.iter().rev().fold(range, |range, lower| lower.source_range(range));
                    (range, label)
                })
            })
            .collect();
        splice(&text, hits)
    }

    fn matches<'s>(&'s self, text: &'s str) -> impl Iterator<Item = (Range<usize>, &'s str)> + 's {
        self.needles.iter().flat_map(move |(needle, label)| {
            text.match_indices(needle.as_str())
                .map(move |(at, _)| (at..at + needle.len(), label.as_str()))
        })
    }
}

/// `text` with each range replaced by its label. Overlapping ranges become one.
fn splice(text: &str, hits: Vec<(Range<usize>, &str)>) -> String {
    let mut sorted = hits;
    sorted.sort_by_key(|(range, _)| (range.start, std::cmp::Reverse(range.end)));
    let mut out = String::with_capacity(text.len());
    let mut done = 0;
    for (range, label) in sorted {
        if range.start < done {
            done = done.max(range.end);
            continue;
        }
        out.push_str(&text[done..range.start]);
        out.push_str(label);
        done = range.end;
    }
    out.push_str(&text[done..]);
    out
}

/// The whole secret, plus the password of a `user:password` login (for Basic
/// auth) when it is long enough to redact without mangling normal text.
fn secret_parts(secret: &str) -> Vec<&str> {
    let password = secret
        .split_once(':')
        .map(|(_, password)| password)
        .filter(|password| password.chars().count() >= MIN_SECRET_LEN);
    std::iter::once(secret).chain(password).collect()
}

/// Every form the vault itself writes a secret in, and then some.
fn encodings(secret: &str) -> Vec<String> {
    let percent = |text: &str| url::form_urlencoded::byte_serialize(text.as_bytes()).collect::<String>();
    let base64 = STANDARD.encode(secret);
    let mut all = vec![
        secret.to_string(),
        percent(secret),
        percent(&base64),
        base64,
        STANDARD_NO_PAD.encode(secret),
        URL_SAFE_NO_PAD.encode(secret),
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
    const FINGERPRINT: &str = "approved-fingerprint";

    fn entry(hosts: &[&str], query_params: &[&str]) -> SecretEntry {
        SecretEntry {
            value: SecretValue::new(TOKEN.to_string()).unwrap(),
            hosts: hosts.iter().map(|h| h.to_string()).collect(),
            query_params: query_params.iter().map(|q| q.to_string()).collect(),
            commands: [("call".to_string(), FINGERPRINT.to_string())].into(),
        }
    }

    fn vault() -> VaultData {
        VaultData::default().with_secret("github", entry(&["api.github.com", "127.0.0.1:8080"], &["key"]))
    }

    fn caller(declared: &[&str], fingerprint: &str) -> Caller {
        Caller {
            name: "call".to_string(),
            declared: declared.iter().map(|d| d.to_string()).collect(),
            fingerprint: fingerprint.to_string(),
        }
    }

    fn injector_for<'a>(vault: &'a VaultData, caller: &'a Caller, url: &'a Url) -> Injector<'a> {
        Injector { vault, caller, url }
    }

    fn header(url: &str, value: &str) -> Result<String> {
        let (vault, who, url) = (vault(), caller(&["github"], FINGERPRINT), Url::parse(url).unwrap());
        let headers = vec![("Authorization".to_string(), value.to_string())];
        Ok(injector_for(&vault, &who, &url).headers(&headers)?.remove(0).1)
    }

    fn inject(url: &str) -> Result<String> {
        header(url, &format!("Bearer {}", placeholder("github", Encoding::Raw)))
    }

    #[test]
    fn injects_into_allowed_host() {
        assert_eq!(inject("https://api.github.com/user").unwrap(), format!("Bearer {TOKEN}"));
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
        assert!(inject("http://127.0.0.1:8080/echo").is_ok());
        assert!(inject("http://localhost:8080/echo").is_err());
    }

    #[test]
    fn local_hosts_only_on_the_bound_port() {
        let err = inject("http://127.0.0.1:9999/catch").unwrap_err().to_string();
        assert!(err.contains("not \"127.0.0.1:9999\""), "{err}");
    }

    #[test]
    fn old_local_rules_without_a_port_are_refused_with_a_fix() {
        let vault = VaultData::default().with_secret("github", entry(&["127.0.0.1"], &[]));
        let (who, url) = (caller(&["github"], FINGERPRINT), Url::parse("http://127.0.0.1:9999/").unwrap());
        let headers = vec![("X".to_string(), placeholder("github", Encoding::Raw))];
        let err = injector_for(&vault, &who, &url).headers(&headers).unwrap_err().to_string();
        assert!(err.contains("without a port"), "{err}");
        assert!(err.contains("tb self vault add github --host 127.0.0.1:<port>"), "{err}");

        let vault = VaultData::default().with_secret("github", entry(&["localhost"], &[]));
        let url = Url::parse("http://localhost:9999/").unwrap();
        let err = injector_for(&vault, &who, &url).headers(&headers).unwrap_err().to_string();
        assert!(err.contains("--host 127.0.0.1:<port>"), "{err}");
    }

    #[test]
    fn refuses_undeclared_and_unknown_secrets() {
        let (vault, url) = (vault(), Url::parse("https://api.github.com/").unwrap());
        let undeclared = caller(&[], FINGERPRINT);
        let headers = vec![("X".to_string(), placeholder("github", Encoding::Raw))];
        let err = injector_for(&vault, &undeclared, &url).headers(&headers).unwrap_err();
        assert!(err.to_string().contains("permissions.vault"));

        let who = caller(&["stripe"], FINGERPRINT);
        let headers = vec![("X".to_string(), placeholder("stripe", Encoding::Raw))];
        let err = injector_for(&vault, &who, &url).headers(&headers).unwrap_err();
        assert!(err.to_string().contains("tb self vault add stripe"));
    }

    #[test]
    fn refuses_commands_the_human_did_not_allow() {
        let (vault, url) = (vault(), Url::parse("https://api.github.com/").unwrap());
        let headers = vec![("X".to_string(), placeholder("github", Encoding::Raw))];

        let edited = caller(&["github"], "something-else");
        let err = injector_for(&vault, &edited, &url).headers(&headers).unwrap_err().to_string();
        assert!(err.contains("changed since"), "{err}");

        let stranger = Caller {
            name: "stranger".to_string(),
            ..caller(&["github"], FINGERPRINT)
        };
        let err = injector_for(&vault, &stranger, &url).headers(&headers).unwrap_err().to_string();
        assert!(err.contains("tb self vault allow github stranger"), "{err}");
    }

    #[test]
    fn host_mistakes_are_reported_before_approval() {
        let (vault, url) = (vault(), Url::parse("https://evil.example/").unwrap());
        let stranger = Caller {
            name: "stranger".to_string(),
            ..caller(&["github"], FINGERPRINT)
        };
        let headers = vec![("X".to_string(), placeholder("github", Encoding::Raw))];
        let err = injector_for(&vault, &stranger, &url).headers(&headers).unwrap_err().to_string();
        assert!(err.contains("may only be sent to"), "{err}");
    }

    #[test]
    fn base64_encoding_for_basic_auth() {
        let value = header(
            "https://api.github.com/",
            &format!("Basic {}", placeholder("github", Encoding::Base64)),
        )
        .unwrap();
        assert_eq!(value, format!("Basic {}", STANDARD.encode(TOKEN)));
        assert_eq!(placeholder("github", Encoding::Base64), "{{vault:github|base64}}");
    }

    #[test]
    fn query_only_in_parameters_the_human_named() {
        let (vault, who, url) = (vault(), caller(&["github"], FINGERPRINT), Url::parse("https://api.github.com/").unwrap());
        let injector = injector_for(&vault, &who, &url);
        let ok = vec![("key".to_string(), placeholder("github", Encoding::Raw)), ("q".to_string(), "x".to_string())];
        assert_eq!(
            injector.query(&ok).unwrap(),
            vec![("key".to_string(), TOKEN.to_string()), ("q".to_string(), "x".to_string())]
        );

        let other = vec![("title".to_string(), placeholder("github", Encoding::Raw))];
        let err = injector.query(&other).unwrap_err().to_string();
        assert!(err.contains("query parameter(s) [\"key\"], not \"title\""), "{err}");

        let in_name = vec![(placeholder("github", Encoding::Raw), "x".to_string())];
        assert!(injector.query(&in_name).unwrap_err().to_string().contains("query parameter name"));
    }

    #[test]
    fn query_names_from_the_script_never_reach_a_suggested_command() {
        let vault = VaultData::default().with_secret("github", entry(&["api.github.com"], &[]));
        let (who, url) = (caller(&["github"], FINGERPRINT), Url::parse("https://api.github.com/").unwrap());
        let pairs = vec![("key --host evil.example".to_string(), placeholder("github", Encoding::Raw))];
        let err = injector_for(&vault, &who, &url).query(&pairs).unwrap_err().to_string();
        assert!(!err.contains("tb self vault add"), "{err}");
        assert!(err.contains("can't be sent in the query parameter"), "{err}");
    }

    #[test]
    fn query_refused_for_header_only_secrets() {
        let vault = VaultData::default().with_secret("github", entry(&["api.github.com"], &[]));
        let (who, url) = (caller(&["github"], FINGERPRINT), Url::parse("https://api.github.com/").unwrap());
        let pairs = vec![("key".to_string(), placeholder("github", Encoding::Raw))];
        let err = injector_for(&vault, &who, &url).query(&pairs).unwrap_err().to_string();
        assert!(err.contains("may only be sent in headers"), "{err}");
        assert!(err.contains("tb self vault add github --host api.github.com --query-param key"), "{err}");
    }

    #[test]
    fn rejects_malformed_placeholders() {
        for bad in ["{{vault:github", "{{vault:Bad Name}}", "{{vault:github|hex}}"] {
            assert!(header("https://api.github.com/", bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn rejects_placeholder_in_header_name() {
        let (vault, who, url) = (vault(), caller(&["github"], FINGERPRINT), Url::parse("https://api.github.com/").unwrap());
        let headers = vec![(placeholder("github", Encoding::Raw), "x".to_string())];
        assert!(injector_for(&vault, &who, &url).headers(&headers).is_err());
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
        let b64_in_query: String = url::form_urlencoded::byte_serialize(b64.as_bytes()).collect();
        let text = format!("echo: {TOKEN} and {b64} and {b64_in_query}");
        let clean = redactor.redact(&text);
        assert!(!clean.contains(TOKEN));
        assert!(!clean.contains(&b64));
        assert_eq!(clean.matches("[REDACTED:github]").count(), 3, "{clean}");
    }

    /// Every character of `text` as a JSON `\uXXXX` escape.
    fn escaped(text: &str) -> String {
        text.chars().map(|c| format!("\\u{:04x}", c as u32)).collect()
    }

    #[test]
    fn redacts_keys_written_with_json_escapes() {
        let redactor = Redactor::new(&vault());
        let label = "[REDACTED:github]";

        let bare = redactor.redact(&format!(r#""{}""#, escaped(TOKEN)));
        assert_eq!(serde_json::from_str::<String>(&bare).unwrap(), label, "{bare}");

        let partly = TOKEN.replacen('g', "\\u0067", 1).replacen('_', "\\u005F", 1);
        let object = redactor.redact(&format!(r#"{{"a":"{partly}"}}"#));
        assert_eq!(serde_json::from_str::<serde_json::Value>(&object).unwrap()["a"], label, "{object}");

        let jsonp = redactor.redact(&format!(r#"cb({{"a":"x{}y"}})"#, escaped(TOKEN)));
        assert_eq!(jsonp, format!(r#"cb({{"a":"x{label}y"}})"#));

        // JSON inside a JSON string: the escapes are escaped once more.
        let nested = redactor.redact(&format!(r#"{{"inner":"{{\"a\":\"{}\"}}"}}"#, escaped(TOKEN).replace('\\', "\\\\")));
        let outer: serde_json::Value = serde_json::from_str(&nested).unwrap();
        let inner: serde_json::Value = serde_json::from_str(outer["inner"].as_str().unwrap()).unwrap();
        assert_eq!(inner["a"], label, "{nested}");
    }

    #[test]
    fn redacts_escaped_characters_outside_the_basic_plane() {
        let secret = "key\u{1F600}value";
        let mut entry = entry(&["x.com"], &[]);
        entry.value = SecretValue::new(secret.to_string()).unwrap();
        let redactor = Redactor::new(&VaultData::default().with_secret("emoji", entry));
        let text = r#""key\ud83d\ude00value""#.to_string();
        assert_eq!(redactor.redact(&text), r#""[REDACTED:emoji]""#);
    }

    #[test]
    fn other_escapes_are_left_alone() {
        let redactor = Redactor::new(&vault());
        let text = r#"{"a":"line\nbreak \u00e9 \\u0041 \/ \x \u12"}"#;
        assert_eq!(redactor.redact(text), text);
    }

    #[test]
    fn redacts_the_password_of_a_login_and_unpadded_base64() {
        let login = "me@example.com:fake_password_123";
        let vault = VaultData::default().with_secret(
            "jira",
            SecretEntry {
                value: SecretValue::new(login.to_string()).unwrap(),
                ..entry(&["api.example.com"], &[])
            },
        );
        let redactor = Redactor::new(&vault);
        let unpadded = STANDARD_NO_PAD.encode(login);
        let clean = redactor.redact(&format!("pw fake_password_123 / {unpadded} / user me@example.com"));
        assert_eq!(clean, "pw [REDACTED:jira] / [REDACTED:jira] / user me@example.com");

        let short = VaultData::default().with_secret(
            "short",
            SecretEntry {
                value: SecretValue::new("user:pass12".to_string()).unwrap(),
                ..entry(&["api.example.com"], &[])
            },
        );
        assert_eq!(Redactor::new(&short).redact("pass12"), "pass12");
    }

    #[test]
    fn empty_redactor_changes_nothing() {
        assert_eq!(Redactor::default().redact("hello"), "hello");
    }
}
