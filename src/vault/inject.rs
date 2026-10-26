use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use anyhow::{Result, anyhow, bail, ensure};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use url::{Host, Url};

use super::approval::{self, Caller};
use super::commands::add_flags;
use super::names::{self, is_secret_name};
use super::{MIN_SECRET_LEN, SecretEntry, SecretValue, VaultData, hosts, scope, unescape};

const PREFIX: &str = "{{vault:";
const SUFFIX: &str = "}}";
const ENCODING_SEPARATOR: char = '|';

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Raw,
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

pub fn ensure_absent(location: &str, text: &str) -> Result<()> {
    ensure!(
        !mentions_vault(text),
        "vault placeholders are only allowed in header values and in `query = {{...}}` parameters, found one in the {location}"
    );
    Ok(())
}

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
        ensure!(is_secret_name(name), "invalid vault secret name {name:?}");
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

#[derive(Debug, Clone, Copy)]
enum Place<'a> {
    Header,
    Query(&'a str),
}

pub type Values = BTreeMap<String, SecretValue>;

type Pairs = Vec<(String, String)>;

pub struct Injector<'a> {
    pub vault: &'a VaultData,
    pub caller: &'a Caller,
    pub method: &'a str,
    pub url: &'a Url,
}

impl<'a> Injector<'a> {
    pub fn authorize_all(&self, headers: &[(String, String)], query: &[(String, String)]) -> Result<BTreeSet<String>> {
        let mut names = BTreeSet::new();
        for (name, value) in headers {
            ensure_absent("header name", name)?;
            names.extend(self.authorized_in(value, Place::Header)?);
        }
        for (name, value) in query {
            ensure_absent("query parameter name", name)?;
            names.extend(self.authorized_in(value, Place::Query(name))?);
        }
        Ok(names)
    }

    pub fn needs_confirmation(&self, names: &BTreeSet<String>) -> Vec<String> {
        names
            .iter()
            .filter(|name| self.vault.get(name).is_some_and(|entry| scope::confirms(&entry.confirm, self.method)))
            .cloned()
            .collect()
    }

    pub fn headers(&self, headers: &[(String, String)], values: &Values) -> Result<Pairs> {
        headers
            .iter()
            .map(|(name, value)| {
                ensure_absent("header name", name)?;
                Ok((name.clone(), self.fill(value, Place::Header, values)?))
            })
            .collect()
    }

    pub fn query(&self, pairs: &[(String, String)], values: &Values) -> Result<Pairs> {
        pairs
            .iter()
            .map(|(name, value)| {
                ensure_absent("query parameter name", name)?;
                Ok((name.clone(), self.fill(value, Place::Query(name), values)?))
            })
            .collect()
    }

    fn authorized_in(&self, text: &str, place: Place) -> Result<Vec<String>> {
        parse(text)?
            .into_iter()
            .filter_map(|piece| match piece {
                Piece::Secret(name, _) => Some(name),
                Piece::Literal(_) => None,
            })
            .map(|name| self.authorize(name, place).map(|_| name.to_string()))
            .collect()
    }

    fn fill(&self, text: &str, place: Place, values: &Values) -> Result<String> {
        parse(text)?
            .into_iter()
            .map(|piece| match piece {
                Piece::Literal(text) => Ok(text.to_string()),
                Piece::Secret(name, encoding) => {
                    self.authorize(name, place)?;
                    let value = values.get(name).ok_or_else(|| anyhow!("no value was prepared for secret {name:?}"))?;
                    Ok(encoding.apply(value.expose()))
                }
            })
            .collect()
    }

    fn authorize(&self, name: &str, place: Place) -> Result<&'a SecretEntry> {
        ensure!(
            names::declared(&self.caller.declared, name),
            "secret {name:?} is not listed in this command's permissions.vault"
        );
        let url = self.url;
        let secure = url.scheme() == "https" || (url.scheme() == "http" && is_loopback(url));
        ensure!(
            secure,
            "secret {name:?} can only be sent over https (plain http only to this computer, like 127.0.0.1:8080)"
        );
        let entry = self.vault.get(name).ok_or_else(|| missing(name, url, place))?;
        check_host(name, entry, url)?;
        check_place(name, entry, place)?;
        check_scope(name, entry, self.method, url)?;
        approval::check(name, entry, self.caller)?;
        Ok(entry)
    }
}

fn check_scope(name: &str, entry: &SecretEntry, method: &str, url: &Url) -> Result<()> {
    ensure!(
        scope::method_allowed(&entry.methods, method),
        "secret {name:?} may only be sent with {}, not {}",
        entry.methods.join(", "),
        method.to_ascii_uppercase()
    );
    if entry.paths.is_empty() {
        return Ok(());
    }
    let path = url.path();
    ensure!(
        !scope::disguised(path),
        "secret {name:?} may only go to some paths, so it can't go to {path:?}: an encoded dot, slash or percent sign, or `..;`, could lead the server to another path"
    );
    ensure!(
        scope::path_allowed(&entry.paths, path),
        "secret {name:?} may only be sent to paths under {}, not {path:?}",
        entry.paths.join(", ")
    );
    Ok(())
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
            add_command(name, &SecretEntry { hosts: fixed, ..entry.clone() })
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
    if !hosts::is_query_param(param) {
        bail!("secret {name:?} can't be sent in the query parameter {param:?}");
    }
    if entry.query_params.is_empty() {
        let wanted = SecretEntry { query_params: vec![param.to_string()], ..entry.clone() };
        bail!(
            "secret {name:?} may only be sent in headers. If the API wants it in the query string, ask the user to run `{}` in their own terminal",
            add_command(name, &wanted)
        );
    }
    bail!(
        "secret {name:?} may only be sent in the query parameter(s) {:?}, not {param:?}",
        entry.query_params
    )
}

fn missing(name: &str, url: &Url, place: Place) -> anyhow::Error {
    let target = match (url.host_str(), url.port()) {
        (Some(host), Some(port)) => format!("{host}:{port}"),
        (Some(host), None) => host.to_string(),
        (None, _) => String::new(),
    };
    let host = hosts::normalize_host(&target).unwrap_or_else(|_| "<host>".to_string());
    let query = match place {
        Place::Query(param) if hosts::is_query_param(param) => format!(" --query-param {param}"),
        _ => String::new(),
    };
    anyhow!(
        "no secret named {name:?} in the vault. Run `tb self vault request {name} --host {host}{query} --why \"<what it is for>\" --note \"<where to get the key>\"`, then ask the user to run `tb self vault setup` in their own terminal"
    )
}

fn local_replacement(rule: &str) -> String {
    match rule.parse::<std::net::Ipv4Addr>() {
        Ok(ip) if ip.is_loopback() => format!("{rule}:<port>"),
        _ => "127.0.0.1:<port>".to_string(),
    }
}

fn add_command(name: &str, entry: &SecretEntry) -> String {
    format!("tb self vault add {name} {}", add_flags(entry))
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

const ESCAPE_LAYERS: usize = 3;

#[derive(Debug, Default)]
pub struct Redactor {
    needles: Vec<(String, String)>,
}

impl Redactor {
    pub fn new(vault: &VaultData, minted: &[(String, SecretValue)]) -> Self {
        let stored = vault
            .secrets
            .iter()
            .flat_map(|(name, entry)| entry.secret_values().into_iter().map(move |value| (name.as_str(), value)));
        let fresh = minted.iter().map(|(name, value)| (name.as_str(), value));
        let mut needles: Vec<(String, String)> = stored
            .chain(fresh)
            .flat_map(|(name, value)| {
                let label = format!("[REDACTED:{name}]");
                secret_parts(value.expose())
                    .into_iter()
                    .flat_map(encodings)
                    .map(move |needle| (needle, label.clone()))
            })
            .collect();
        needles.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(&b.0)));
        needles.dedup_by(|a, b| a.0 == b.0);
        Self { needles }
    }

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

    fn redact_escaped(&self, text: String) -> String {
        if self.needles.is_empty() || !text.contains('\\') {
            return text;
        }
        let layers = unescape::layers(&text, ESCAPE_LAYERS);
        let hits: Vec<(Range<usize>, &str)> = layers
            .iter()
            .enumerate()
            .flat_map(|(depth, layer)| {
                let below = layers.iter().take(depth + 1).rev();
                self.matches(&layer.text).map(move |(range, label)| {
                    let range = below.clone().fold(range, |range, lower| lower.source_range(range));
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

fn secret_parts(secret: &str) -> Vec<&str> {
    let password = secret
        .split_once(':')
        .map(|(_, password)| password)
        .filter(|password| password.chars().count() >= MIN_SECRET_LEN);
    std::iter::once(secret).chain(password).collect()
}

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
            query_params: query_params.iter().map(std::string::ToString::to_string).collect(),
            commands: [("call".to_string(), FINGERPRINT.to_string())].into(),
            ..SecretEntry::new(
                SecretValue::new(TOKEN.to_string()).unwrap(),
                hosts.iter().map(std::string::ToString::to_string).collect(),
            )
        }
    }

    fn vault() -> VaultData {
        VaultData::default().with_secret("github", entry(&["api.github.com", "127.0.0.1:8080"], &["key"]))
    }

    fn caller(declared: &[&str], fingerprint: &str) -> Caller {
        Caller {
            name: "call".to_string(),
            declared: declared.iter().map(std::string::ToString::to_string).collect(),
            fingerprint: fingerprint.to_string(),
        }
    }

    struct Sender<'a>(Injector<'a>);

    impl Sender<'_> {
        fn headers(&self, headers: &[(String, String)]) -> Result<Vec<(String, String)>> {
            let names = self.0.authorize_all(headers, &[])?;
            self.0.headers(headers, &stored(self.0.vault, &names))
        }

        fn query(&self, pairs: &[(String, String)]) -> Result<Vec<(String, String)>> {
            let names = self.0.authorize_all(&[], pairs)?;
            self.0.query(pairs, &stored(self.0.vault, &names))
        }
    }

    fn stored(vault: &VaultData, names: &BTreeSet<String>) -> Values {
        names
            .iter()
            .filter_map(|name| vault.get(name).map(|entry| (name.clone(), entry.value.clone())))
            .collect()
    }

    fn injector_for<'a>(vault: &'a VaultData, caller: &'a Caller, url: &'a Url) -> Sender<'a> {
        sending(vault, caller, "GET", url)
    }

    fn sending<'a>(vault: &'a VaultData, caller: &'a Caller, method: &'a str, url: &'a Url) -> Sender<'a> {
        Sender(Injector { vault, caller, method, url })
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
        let err = injector_for(&vault, &who, &url).headers(&headers).unwrap_err().to_string();
        assert!(err.contains("tb self vault request stripe --host api.github.com --why"), "{err}");
        assert!(err.contains("tb self vault setup"), "{err}");
    }

    #[test]
    fn a_missing_key_hint_only_names_hosts_and_parameters_the_cli_accepts() {
        let who = caller(&["stripe"], FINGERPRINT);
        let hint = |url: &str, pairs: Vec<(String, String)>| {
            let (vault, url) = (vault(), Url::parse(url).unwrap());
            injector_for(&vault, &who, &url).query(&pairs).unwrap_err().to_string()
        };
        let key = |name: &str| vec![(name.to_string(), placeholder("stripe", Encoding::Raw))];
        let err = hint("https://api.stripe.com:8443/", key("key"));
        assert!(err.contains("request stripe --host api.stripe.com:8443 --query-param key --why"), "{err}");
        let err = hint("http://localhost:8080/", key("key --host evil.example"));
        assert!(err.contains("request stripe --host <host> --why"), "{err}");
        assert!(!err.contains("evil.example"), "{err}");
        let err = hint("http://api.stripe.com/", key("key"));
        assert!(err.contains("only be sent over https") && !err.contains("vault request"), "{err}");
    }

    #[test]
    fn a_pattern_still_needs_each_key_allowed() {
        let work = entry(&["api.github.com"], &[]);
        let personal = SecretEntry { commands: std::collections::BTreeMap::default(), ..work.clone() };
        let vault = VaultData::default()
            .with_secret("github/work", work)
            .with_secret("github/personal", personal);
        let (who, url) = (caller(&["github/*"], FINGERPRINT), Url::parse("https://api.github.com/").unwrap());
        let send = |name: &str| {
            let headers = vec![("X".to_string(), placeholder(name, Encoding::Raw))];
            injector_for(&vault, &who, &url)
                .headers(&headers)
                .map(|mut filled| filled.remove(0).1)
                .map_err(|err| err.to_string())
        };
        assert_eq!(send("github/work").unwrap(), TOKEN);
        let err = send("github/personal").unwrap_err();
        assert!(err.contains("tb self vault setup call"), "{err}");
        assert!(send("gitlab/work").unwrap_err().contains("permissions.vault"));
        assert!(send("github/*").unwrap_err().contains("invalid vault secret name"));
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
        assert!(err.contains("tb self vault setup stranger"), "{err}");
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

    fn scoped(methods: &[&str], paths: &[&str]) -> VaultData {
        let strings = |items: &[&str]| items.iter().map(std::string::ToString::to_string).collect();
        let github = SecretEntry { methods: strings(methods), paths: strings(paths), ..entry(&["api.github.com"], &[]) };
        VaultData::default().with_secret("github", github)
    }

    fn send_as(vault: &VaultData, who: &Caller, method: &str, url: &str) -> Result<String> {
        let url = Url::parse(url).unwrap();
        let headers = vec![("X".to_string(), placeholder("github", Encoding::Raw))];
        Ok(sending(vault, who, method, &url).headers(&headers)?.remove(0).1)
    }

    #[test]
    fn keys_only_go_with_the_methods_the_human_named() {
        let (vault, who) = (scoped(&["GET", "HEAD"], &[]), caller(&["github"], FINGERPRINT));
        assert_eq!(send_as(&vault, &who, "get", "https://api.github.com/user").unwrap(), TOKEN);
        let err = send_as(&vault, &who, "delete", "https://api.github.com/repos/a/b").unwrap_err().to_string();
        assert_eq!(err, r#"secret "github" may only be sent with GET, HEAD, not DELETE"#);
    }

    #[test]
    fn keys_only_go_to_the_paths_the_human_named() {
        let (vault, who) = (scoped(&[], &["/repos/acme", "/user"]), caller(&["github"], FINGERPRINT));
        for ok in ["https://api.github.com/repos/acme/x/issues?state=open", "https://api.github.com/user"] {
            assert_eq!(send_as(&vault, &who, "GET", ok).unwrap(), TOKEN, "{ok}");
        }
        for (url, why) in [
            ("https://api.github.com/repos/acmex", "may only be sent to paths under /repos/acme, /user"),
            ("https://api.github.com/repos/acme/../../orgs/x", "not \"/orgs/x\""),
            ("https://api.github.com/repos/acme/x%2F..%2F..%2Fuser", "could lead the server to another path"),
            ("https://api.github.com/repos/acme/..;/other", "could lead the server to another path"),
        ] {
            let err = send_as(&vault, &who, "GET", url).unwrap_err().to_string();
            assert!(err.contains(why), "{url}: {err}");
        }
    }

    #[test]
    fn scope_mistakes_are_reported_before_approval() {
        let vault = scoped(&["GET"], &["/user"]);
        let stranger = Caller { name: "stranger".to_string(), ..caller(&["github"], FINGERPRINT) };
        let err = send_as(&vault, &stranger, "POST", "https://api.github.com/user").unwrap_err().to_string();
        assert!(err.contains("may only be sent with GET"), "{err}");
        let err = send_as(&vault, &stranger, "GET", "https://api.github.com/other").unwrap_err().to_string();
        assert!(err.contains("paths under /user"), "{err}");
        let err = send_as(&vault, &stranger, "GET", "https://api.github.com/user").unwrap_err().to_string();
        assert!(err.contains("tb self vault setup stranger"), "{err}");
    }

    #[test]
    fn suggested_commands_keep_every_rule_the_key_has() {
        let narrow = SecretEntry {
            methods: vec!["GET".into()],
            paths: vec!["/v1".into()],
            confirm: vec!["writes".into()],
            ..entry(&["api.example.com"], &[])
        };
        let vault = VaultData::default().with_secret("github", narrow);
        let (who, url) = (caller(&["github"], FINGERPRINT), Url::parse("https://api.example.com/v1").unwrap());
        let pairs = vec![("key".to_string(), placeholder("github", Encoding::Raw))];
        let err = injector_for(&vault, &who, &url).query(&pairs).unwrap_err().to_string();
        assert!(
            err.contains("tb self vault add github --host api.example.com --query-param key --method GET --path /v1 --confirm writes"),
            "{err}"
        );
    }

    #[test]
    fn only_keys_set_to_ask_need_confirmation() {
        let asks = SecretEntry { confirm: vec!["writes".into()], ..entry(&["api.github.com"], &[]) };
        let vault = VaultData::default().with_secret("github", asks).with_secret("other", entry(&["api.github.com"], &[]));
        let (who, url) = (caller(&["github", "other"], FINGERPRINT), Url::parse("https://api.github.com/").unwrap());
        let names: BTreeSet<String> = ["github".to_string(), "other".to_string()].into();
        let post = Injector { vault: &vault, caller: &who, method: "POST", url: &url };
        assert_eq!(post.needs_confirmation(&names), ["github"]);
        let get = Injector { method: "GET", ..post };
        assert!(get.needs_confirmation(&names).is_empty());
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
        let redactor = Redactor::new(&vault(), &[]);
        let b64 = STANDARD.encode(TOKEN);
        let b64_in_query: String = url::form_urlencoded::byte_serialize(b64.as_bytes()).collect();
        let text = format!("echo: {TOKEN} and {b64} and {b64_in_query}");
        let clean = redactor.redact(&text);
        assert!(!clean.contains(TOKEN));
        assert!(!clean.contains(&b64));
        assert_eq!(clean.matches("[REDACTED:github]").count(), 3, "{clean}");
    }

    fn escaped(text: &str) -> String {
        text.chars().map(|c| format!("\\u{:04x}", u32::from(c))).collect::<Vec<_>>().concat()
    }

    #[test]
    fn redacts_keys_written_with_json_escapes() {
        let redactor = Redactor::new(&vault(), &[]);
        let label = "[REDACTED:github]";

        let bare = redactor.redact(&format!(r#""{}""#, escaped(TOKEN)));
        assert_eq!(serde_json::from_str::<String>(&bare).unwrap(), label, "{bare}");

        let partly = TOKEN.replacen('g', "\\u0067", 1).replacen('_', "\\u005F", 1);
        let object = redactor.redact(&format!(r#"{{"a":"{partly}"}}"#));
        assert_eq!(serde_json::from_str::<serde_json::Value>(&object).unwrap()["a"], label, "{object}");

        let jsonp = redactor.redact(&format!(r#"cb({{"a":"x{}y"}})"#, escaped(TOKEN)));
        assert_eq!(jsonp, format!(r#"cb({{"a":"x{label}y"}})"#));

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
        let redactor = Redactor::new(&VaultData::default().with_secret("emoji", entry), &[]);
        let text = r#""key\ud83d\ude00value""#.to_string();
        assert_eq!(redactor.redact(&text), r#""[REDACTED:emoji]""#);
    }

    #[test]
    fn other_escapes_are_left_alone() {
        let redactor = Redactor::new(&vault(), &[]);
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
        let redactor = Redactor::new(&vault, &[]);
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
        assert_eq!(Redactor::new(&short, &[]).redact("pass12"), "pass12");
    }

    #[test]
    fn empty_redactor_changes_nothing() {
        assert_eq!(Redactor::default().redact("hello"), "hello");
    }
}
