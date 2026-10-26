use std::collections::BTreeSet;

use anyhow::{Result, anyhow, ensure};
use url::{Url, form_urlencoded};

const MAX_METHOD_LEN: usize = 16;
const MAX_PATH_LEN: usize = 200;
pub const ALL: &str = "all";
pub const WRITES: &str = "writes";
const READS: [&str; 3] = ["GET", "HEAD", "OPTIONS"];
const CONFIRMABLE: [&str; 7] = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"];
const DISGUISES: [&str; 8] = ["%2e", "%2f", "%5c", "%25", "%00", "%u", "%c0", "%c1"];
const OVERRIDE_HEADERS: [&str; 3] = ["x-http-method-override", "x-http-method", "x-method-override"];
const OVERRIDE_FIELD: &str = "_method";

pub fn normalize_method(raw: &str) -> Result<String> {
    let method = raw.trim().to_ascii_uppercase();
    ensure!(is_method(&method), "{raw:?} is not an HTTP method. Use one like GET, POST or DELETE");
    Ok(method)
}

fn is_method(method: &str) -> bool {
    !method.is_empty() && method.len() <= MAX_METHOD_LEN && method.chars().all(|c| c.is_ascii_uppercase())
}

pub fn normalize_confirm(raw: &[String]) -> Result<Vec<String>> {
    let mut rules = BTreeSet::new();
    for item in raw {
        let word = item.trim();
        let rule = match word.to_ascii_lowercase().as_str() {
            ALL => ALL.to_string(),
            WRITES => WRITES.to_string(),
            _ => {
                let method = word.to_ascii_uppercase();
                ensure!(
                    CONFIRMABLE.contains(&method.as_str()),
                    "{item:?} is not a --confirm choice. Use all, writes (anything but GET, HEAD and OPTIONS), or methods from {}",
                    CONFIRMABLE.join(", ")
                );
                method
            }
        };
        rules.insert(rule);
    }
    if rules.contains(ALL) {
        return Ok(vec![ALL.to_string()]);
    }
    let writes = rules.contains(WRITES);
    Ok(rules
        .into_iter()
        .filter(|rule| !writes || rule == WRITES || READS.contains(&rule.as_str()))
        .collect())
}

pub fn normalize_path(raw: &str) -> Result<String> {
    let path = raw.trim();
    let invalid = |why: &str| anyhow!("{raw:?} is not a path rule: {why}. Use one like /repos/acme");
    ensure!(path.starts_with('/'), invalid("it must start with /"));
    ensure!(path.len() <= MAX_PATH_LEN, invalid(&format!("it is longer than {MAX_PATH_LEN} characters")));
    let plain = path
        .chars()
        .all(|c| c.is_ascii_graphic() && !matches!(c, '?' | '#' | '%' | '\\' | '*'));
    ensure!(plain, invalid("use letters, digits, - _ . and /, with no query, wildcard or %-escape"));
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return Ok("/".to_string());
    }
    let clean = trimmed.split('/').skip(1).all(|segment| !matches!(segment, "" | "." | ".."));
    ensure!(clean, invalid("it has an empty, . or .. part"));
    Ok(trimmed.to_string())
}

pub fn method_allowed(methods: &[String], method: &str) -> bool {
    methods.is_empty() || methods.iter().any(|allowed| allowed.eq_ignore_ascii_case(method))
}

pub fn path_allowed(paths: &[String], path: &str) -> bool {
    paths.is_empty()
        || paths.iter().any(|rule| {
            rule == "/" || path == rule || path.strip_prefix(rule.as_str()).is_some_and(|rest| rest.starts_with('/'))
        })
}

pub fn disguised(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    DISGUISES.iter().any(|escape| lower.contains(escape)) || path.contains('\\') || path.split('/').any(only_dots)
}

fn only_dots(segment: &str) -> bool {
    let before_params = segment.split(';').next().unwrap_or_default();
    let decoded: String = percent_encoding::percent_decode_str(before_params).decode_utf8_lossy().into_owned();
    let trimmed = decoded.trim_matches(|c: char| c.is_whitespace());
    !trimmed.is_empty() && trimmed.chars().all(|c| c == '.')
}

pub struct Sent<'a> {
    pub headers: &'a [(String, String)],
    pub query: &'a [(String, String)],
    pub url: &'a Url,
    pub body: &'a [u8],
}

pub fn method_override(sent: &Sent) -> Option<String> {
    if let Some((name, _)) = sent.headers.iter().find(|(name, _)| OVERRIDE_HEADERS.contains(&name.to_ascii_lowercase().as_str())) {
        return Some(format!("the {name} header"));
    }
    let in_query = sent.query.iter().any(|(name, _)| name == OVERRIDE_FIELD)
        || sent.url.query_pairs().any(|(name, _)| name == OVERRIDE_FIELD);
    let in_form = form_urlencoded::parse(sent.body).any(|(name, _)| name == OVERRIDE_FIELD);
    let in_json = serde_json::from_slice::<serde_json::Value>(sent.body).is_ok_and(|body| body.get(OVERRIDE_FIELD).is_some());
    (in_query || in_form || in_json).then(|| format!("a {OVERRIDE_FIELD} field"))
}

pub fn confirms(confirm: &[String], method: &str) -> bool {
    let method = method.to_ascii_uppercase();
    confirm
        .iter()
        .any(|rule| rule == ALL || (rule == WRITES && !READS.contains(&method.as_str())) || *rule == method)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(std::string::ToString::to_string).collect()
    }

    #[test]
    fn methods_are_upper_case_words() {
        assert_eq!(normalize_method(" get ").unwrap(), "GET");
        for bad in ["", "G ET", "GET1", "PO-ST", &"A".repeat(17)] {
            assert!(normalize_method(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn confirm_takes_all_writes_or_known_methods() {
        assert_eq!(normalize_confirm(&strings(&["Writes"])).unwrap(), [WRITES]);
        assert_eq!(normalize_confirm(&strings(&["post", "delete"])).unwrap(), ["DELETE", "POST"]);
        assert_eq!(normalize_confirm(&strings(&["POST", "ALL"])).unwrap(), [ALL]);
        assert_eq!(normalize_confirm(&strings(&["POST", "get", "writes"])).unwrap(), ["GET", WRITES]);
        assert!(normalize_confirm(&[]).unwrap().is_empty());
        for typo in ["sometimes", "PSOT", "always", "*"] {
            let err = normalize_confirm(&strings(&[typo])).unwrap_err().to_string();
            assert!(err.contains("all, writes"), "{typo}: {err}");
        }
    }

    #[test]
    fn writes_are_every_method_but_the_reads() {
        let writes = strings(&[WRITES]);
        for write in ["post", "PUT", "PATCH", "DELETE", "PURGE", "MKCOL"] {
            assert!(confirms(&writes, write), "{write} should ask");
        }
        for read in ["GET", "head", "OPTIONS"] {
            assert!(!confirms(&writes, read), "{read} should not ask");
        }
        assert!(confirms(&strings(&[ALL]), "GET"));
        assert!(confirms(&strings(&["POST"]), "post") && !confirms(&strings(&["POST"]), "PUT"));
        assert!(!confirms(&[], "DELETE"));
    }

    #[test]
    fn path_rules_are_plain_prefixes() {
        assert_eq!(normalize_path(" /repos/acme/ ").unwrap(), "/repos/acme");
        assert_eq!(normalize_path("/").unwrap(), "/");
        assert_eq!(normalize_path("//").unwrap(), "/");
        assert_eq!(normalize_path("/v1.2/files_x-y").unwrap(), "/v1.2/files_x-y");
        for bad in [
            "", "repos", "/a//b", "/a/../b", "/a/./b", "/a?x=1", "/a#b", "/a%2fb", "/a\\b", "/a*", "/a b", "/ø",
            &format!("/{}", "a".repeat(200)),
        ] {
            assert!(normalize_path(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn paths_match_whole_segments() {
        let rules = strings(&["/repos/acme", "/user"]);
        for ok in ["/repos/acme", "/repos/acme/", "/repos/acme/x/issues", "/user"] {
            assert!(path_allowed(&rules, ok), "{ok} should match");
        }
        for no in ["/repos/acmex", "/repos", "/users", "/", "/repos/acm"] {
            assert!(!path_allowed(&rules, no), "{no} should not match");
        }
        assert!(path_allowed(&[], "/anything"));
        assert!(path_allowed(&strings(&["/"]), "/anything"));
    }

    #[test]
    fn methods_match_without_case() {
        let rules = strings(&["GET", "HEAD"]);
        assert!(method_allowed(&rules, "get") && method_allowed(&rules, "HEAD"));
        assert!(!method_allowed(&rules, "POST"));
        assert!(method_allowed(&[], "DELETE"));
    }

    #[test]
    fn paths_a_server_could_read_differently_are_disguised() {
        for tricky in [
            "/repos/acme/x%2F..%2F..%2Fuser",
            "/repos/acme/%2e%2e/user",
            "/repos/acme/..;/user",
            "/repos/acme/.;x/user",
            "/repos/acme/%5c..",
            "/repos/acme/%252e%252e/user",
        ] {
            assert!(disguised(tricky), "{tricky} should be refused");
        }
        for plain in ["/repos/acme/issues", "/repos/acme/a;b", "/v1/files/report.pdf", "/a/..b"] {
            assert!(!disguised(plain), "{plain} should be fine");
        }
        for odd in ["/repos/acme/.../x", "/repos/acme/..%20/x", "/repos/acme/%00", "/repos/acme/%u002e%u002e", "/repos/acme/%c0%ae%c0%ae"] {
            assert!(disguised(odd), "{odd} should be refused");
        }
    }

    #[test]
    fn method_overrides_are_found_in_headers_query_and_body() {
        let url = Url::parse("https://x.example/a?b=1").unwrap();
        let none: Vec<(String, String)> = Vec::new();
        let sent = |headers: &[(String, String)], query: &[(String, String)], url: &Url, body: &[u8]| {
            method_override(&Sent { headers, query, url, body })
        };
        assert_eq!(sent(&none, &none, &url, b"title=x"), None);
        let header = vec![("X-HTTP-Method-Override".to_string(), "DELETE".to_string())];
        assert_eq!(sent(&header, &none, &url, b"").as_deref(), Some("the X-HTTP-Method-Override header"));
        let query = vec![("_method".to_string(), "DELETE".to_string())];
        assert!(sent(&none, &query, &url, b"").is_some());
        assert!(sent(&none, &none, &Url::parse("https://x.example/?_method=put").unwrap(), b"").is_some());
        assert!(sent(&none, &none, &url, b"a=1&_method=delete").is_some());
        assert!(sent(&none, &none, &url, br#"{"_method":"DELETE"}"#).is_some());
        assert!(sent(&none, &none, &url, br#"{"method":"DELETE"}"#).is_none());
    }
}
