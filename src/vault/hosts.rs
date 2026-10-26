use std::net::Ipv4Addr;

use anyhow::{Result, anyhow, ensure};
use url::{Host, Url};

const MAX_QUERY_PARAM_LEN: usize = 64;
const IPV6_LOOPBACK: &str = "[::1]";

pub fn normalize_host(raw: &str) -> Result<String> {
    let invalid = || {
        anyhow!(
            "{raw:?} is not a valid host. Use a hostname like api.github.com, with a port if needed like api.example.com:8443 (no scheme, path or wildcard)"
        )
    };
    let lowered = raw.trim().to_ascii_lowercase();
    let (name, port) = split_port(&lowered).ok_or_else(invalid)?;
    let name = canonical(name).ok_or_else(invalid)?;
    if !is_local(&name) {
        return Ok(port.map_or(name.clone(), |port| format!("{name}:{port}")));
    }
    ensure!(
        is_loopback_ip(&name),
        "{raw:?} is on this computer. Use the address your server listens on, like 127.0.0.1:8080 or [::1]:8080: localhost can mean either, and another program could listen on the one your server doesn't use"
    );
    let port = port.ok_or_else(|| {
        anyhow!(
            "{raw:?} is on this computer, so it needs a port, like {name}:8080. Without one, any program here (an AI agent included) could listen on a port of its choosing and receive the key"
        )
    })?;
    Ok(format!("{name}:{port}"))
}

fn split_port(text: &str) -> Option<(&str, Option<u16>)> {
    let name_end = if text.starts_with('[') {
        text.find(']')? + 1
    } else {
        text.find(':').unwrap_or(text.len())
    };
    let (name, rest) = text.split_at(name_end);
    if rest.is_empty() {
        return Some((name, None));
    }
    let port = rest.strip_prefix(':')?.parse::<u16>().ok().filter(|port| *port != 0)?;
    Some((name, Some(port)))
}

fn canonical(name: &str) -> Option<String> {
    if name.starts_with('[') {
        return match Host::parse(name).ok()? {
            Host::Ipv6(ip) if ip.is_loopback() => Some(IPV6_LOOPBACK.to_string()),
            _ => None,
        };
    }
    let valid_chars = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    if name.is_empty() || !valid_chars || name.starts_with('.') || name.ends_with('.') {
        return None;
    }
    match Host::parse(name).ok()? {
        Host::Domain(domain) => Some(domain),
        Host::Ipv4(ip) => Some(ip.to_string()),
        Host::Ipv6(_) => None,
    }
}

pub fn is_local(host: &str) -> bool {
    host == "localhost"
        || host.ends_with(".localhost")
        || host == IPV6_LOOPBACK
        || host
            .parse::<Ipv4Addr>()
            .is_ok_and(|ip| ip.is_loopback() || ip.is_unspecified())
}

fn is_loopback_ip(host: &str) -> bool {
    host == IPV6_LOOPBACK || host.parse::<Ipv4Addr>().is_ok_and(|ip| ip.is_loopback())
}

pub fn allows(rule: &str, url: &Url) -> bool {
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    match split_port(rule) {
        Some((name, Some(port))) => {
            name == host
                && url.port_or_known_default() == Some(port)
                && (!is_local(name) || is_loopback_ip(name))
        }
        Some((name, None)) => name == host && !is_local(name),
        None => false,
    }
}

pub fn rule_host(rule: &str) -> &str {
    split_port(rule).map_or(rule, |(name, _)| name)
}

pub fn local_note(rules: &[String]) -> Option<String> {
    let local: Vec<&str> = rules
        .iter()
        .map(String::as_str)
        .filter(|rule| is_local(rule_host(rule)))
        .collect();
    (!local.is_empty()).then(|| {
        format!(
            "Note: {} is on this computer, and whatever listens there gets the key. Have your server listen on exactly that address (not 0.0.0.0), or another program can take its connections. While it is stopped, any program can.",
            local.join(", ")
        )
    })
}

pub fn normalize_query_param(raw: &str) -> Result<String> {
    let name = raw.trim();
    ensure!(
        is_query_param(name),
        "{raw:?} is not a valid query parameter name. Use letters, digits, '-', '_' or '.', like key or api_key"
    );
    Ok(name.to_string())
}

pub fn is_query_param(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_QUERY_PARAM_LEN
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(text: &str) -> Url {
        Url::parse(text).unwrap()
    }

    #[test]
    fn hosts_are_normalized() {
        assert_eq!(normalize_host(" API.GitHub.com ").unwrap(), "api.github.com");
        assert_eq!(normalize_host("api.example.com:8443").unwrap(), "api.example.com:8443");
        assert_eq!(normalize_host("127.0.0.1:8080").unwrap(), "127.0.0.1:8080");
        assert_eq!(normalize_host("127.1:9000").unwrap(), "127.0.0.1:9000");
        assert_eq!(normalize_host("0x7f.0.0.1:9000").unwrap(), "127.0.0.1:9000");
        assert_eq!(normalize_host("[0:0::1]:9000").unwrap(), "[::1]:9000");
    }

    #[test]
    fn bad_hosts_are_rejected() {
        for bad in [
            "", "*", "*.github.com", "https://x.com", "x.com/path", ".x.com", "x.com:", "x.com:0",
            "x.com:99999", "x.com:80:80", "x.123", "[2001:db8::1]:80", "[::1", "[::1]x", "::1",
        ] {
            assert!(normalize_host(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn this_computer_needs_one_address_and_a_port() {
        for name in ["localhost:8080", "app.localhost:8080", "0.0.0.0:8080", "localhost"] {
            let err = normalize_host(name).unwrap_err().to_string();
            assert!(err.contains("127.0.0.1:8080 or [::1]:8080"), "{name}: {err}");
        }
        for ip in ["127.0.0.1", "127.1", "[::1]"] {
            let err = normalize_host(ip).unwrap_err().to_string();
            assert!(err.contains("needs a port"), "{ip}: {err}");
        }
    }

    #[test]
    fn rules_match_host_and_port() {
        assert!(allows("api.github.com", &url("https://api.github.com/user")));
        assert!(allows("api.github.com", &url("https://API.GitHub.com:8443/")));
        assert!(!allows("api.github.com", &url("https://api.github.com.evil.example/")));
        assert!(!allows("api.github.com", &url("https://api.github.com@evil.example/")));

        assert!(allows("127.0.0.1:8080", &url("http://127.0.0.1:8080/x")));
        assert!(!allows("127.0.0.1:8080", &url("http://127.0.0.1:8081/x")));
        assert!(!allows("127.0.0.1:8080", &url("http://localhost:8080/x")));
        assert!(allows("[::1]:8080", &url("http://[::1]:8080/x")));
        assert!(!allows("[::1]:8080", &url("http://127.0.0.1:8080/x")));
        assert!(allows("api.example.com:443", &url("https://api.example.com/")));
        assert!(!allows("api.example.com:443", &url("http://api.example.com/")));
    }

    #[test]
    fn local_rules_that_are_no_longer_valid_match_nothing() {
        assert!(!allows("127.0.0.1", &url("http://127.0.0.1:9999/")));
        assert!(!allows("localhost", &url("http://localhost/")));
        assert!(!allows("localhost:8080", &url("http://localhost:8080/")));
        assert!(!allows("0.0.0.0:8080", &url("http://0.0.0.0:8080/")));
        assert!(!allows("x.com:nope", &url("https://x.com/")));
    }

    #[test]
    fn local_note_names_only_local_rules() {
        assert_eq!(local_note(&["api.github.com".into()]), None);
        let note = local_note(&["api.github.com".into(), "[::1]:8080".into()]).unwrap();
        assert!(note.contains("[::1]:8080") && !note.contains("github"), "{note}");
    }

    #[test]
    fn query_param_rules() {
        assert_eq!(normalize_query_param(" api_Key ").unwrap(), "api_Key");
        for bad in ["", "a b", "k=v", "a&b", "key --host x", &"k".repeat(65)] {
            assert!(normalize_query_param(bad).is_err(), "{bad} should be rejected");
        }
    }
}
