//! Key names with folders: `github`, `github/work`, `github/work/token`. A command
//! may list a pattern like `github/*` in `permissions.vault`, so one command can
//! serve several accounts. Each key still needs its own `tb self vault allow`.

use crate::manifest::is_valid_name;

/// `service/account/key` is as deep as names go.
const MAX_PARTS: usize = 3;
const SEPARATOR: char = '/';
/// Stands for one whole part, never the first: the service is always named.
const WILDCARD: &str = "*";

/// The name rules, for error messages.
pub const NAME_RULES: &str =
    "1-3 parts split by '/', each 1-64 chars of a-z, 0-9, '-', '_' starting with a letter or digit, like github or github/work";

/// A key name: 1 to `MAX_PARTS` valid names joined by `/`.
pub fn is_secret_name(name: &str) -> bool {
    parts(name).is_some_and(|parts| parts.iter().all(|part| is_valid_name(part)))
}

/// A `permissions.vault` entry: a key name, or one with `*` for any part but the first.
pub fn is_secret_pattern(pattern: &str) -> bool {
    parts(pattern).is_some_and(|parts| {
        is_valid_name(parts[0]) && parts[1..].iter().all(|part| *part == WILDCARD || is_valid_name(part))
    })
}

/// Whether `pattern` covers the key `name`. `*` matches exactly one part, so
/// `github/*` covers `github/work` but not `github` or `github/work/token`.
pub fn matches(pattern: &str, name: &str) -> bool {
    let (Some(wanted), Some(parts)) = (parts(pattern), parts(name)) else {
        return false;
    };
    is_secret_pattern(pattern)
        && is_secret_name(name)
        && wanted.len() == parts.len()
        && wanted.iter().zip(&parts).all(|(want, part)| *want == WILDCARD || want == part)
}

/// The `/`-separated parts of `text`, unless there are more than `MAX_PARTS`.
fn parts(text: &str) -> Option<Vec<&str>> {
    let parts: Vec<&str> = text.split(SEPARATOR).collect();
    (parts.len() <= MAX_PARTS).then_some(parts)
}

/// Whether any of a command's `permissions.vault` entries covers `name`.
pub fn declared(entries: &[String], name: &str) -> bool {
    entries.iter().any(|entry| matches(entry, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_have_one_to_three_parts() {
        for name in ["github", "github/work", "github/work/token", "a-b/c_d/0"] {
            assert!(is_secret_name(name), "{name}");
        }
        let too_long = format!("github/{}", "a".repeat(65));
        for name in ["", "/", "github/", "/work", "github//work", "a/b/c/d", "github/Work", "github/*", "github/../x", "github\\work", "github/wo rk", &too_long] {
            assert!(!is_secret_name(name), "{name}");
        }
    }

    #[test]
    fn patterns_name_the_service_and_star_whole_parts() {
        for pattern in ["github", "github/work", "github/*", "github/*/token", "github/work/*", "github/*/*"] {
            assert!(is_secret_pattern(pattern), "{pattern}");
        }
        for pattern in ["", "*", "*/work", "github/wo*", "github/**", "github/*/*/*", "github/", "github//*", "Bad Name"] {
            assert!(!is_secret_pattern(pattern), "{pattern}");
        }
    }

    #[test]
    fn a_star_matches_exactly_one_part() {
        assert!(matches("github", "github"));
        assert!(matches("github/*", "github/work"));
        assert!(matches("github/*/token", "github/work/token"));
        assert!(matches("github/work/*", "github/work/token"));
        assert!(matches("github/*/*", "github/work/token"));
        assert!(!matches("github/*/*", "github/work"));
        assert!(!matches("github", "github/work"));
        assert!(!matches("github/*", "github"));
        assert!(!matches("github/*", "github/work/token"));
        assert!(!matches("github/*/token", "github/work/app-key"));
        assert!(!matches("github/*", "gitlab/work"));
    }

    #[test]
    fn only_real_names_match() {
        for name in ["github/*", "github/Work", "github/", "github/../x"] {
            assert!(!matches("github/*", name), "{name}");
        }
        assert!(!matches("*", "github"));
    }

    #[test]
    fn declared_checks_every_entry() {
        let entries = vec!["stripe".to_string(), "github/*".to_string()];
        assert!(declared(&entries, "stripe"));
        assert!(declared(&entries, "github/work"));
        assert!(!declared(&entries, "github"));
        assert!(!declared(&entries, "stripe/live"));
        assert!(!declared(&[], "stripe"));
    }
}
