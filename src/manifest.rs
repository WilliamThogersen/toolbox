//! `command.json`: the declarative half of a command (name, args, permissions).

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Top-level names owned by toolbox itself (built-ins live under `self`).
pub const RESERVED_NAMES: &[&str] = &["self", "help"];

const MAX_NAME_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub name: String,
    /// Semver like `1.2.0`. `tb self update` only replaces an installed copy with a higher one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub description: String,
    #[serde(default)]
    pub args: BTreeMap<String, ArgSpec>,
    #[serde(default)]
    pub permissions: Permissions,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArgSpec {
    #[serde(rename = "type")]
    pub kind: ArgType,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ArgType {
    String,
    Integer,
    Number,
    Boolean,
}

/// What a command's script is allowed to touch.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Permissions {
    /// Hosts the script may call. `"*"` allows any host.
    #[serde(default)]
    pub http: Vec<String>,
    /// Vault secret names the script may reference.
    #[serde(default)]
    pub vault: Vec<String>,
    /// Programs the script may run with `exec`.
    #[serde(default)]
    pub exec: Vec<String>,
    /// Environment variables the script may read.
    #[serde(default)]
    pub env: Vec<String>,
}

impl Manifest {
    pub fn parse(json: &str) -> Result<Self> {
        serde_json::from_str(json).context("invalid command.json")
    }

    /// `None` when there is no version or it is not valid semver.
    pub fn semver(&self) -> Option<Version> {
        self.version.as_deref().and_then(|v| Version::parse(v).ok())
    }

    /// Returns every problem found; an empty list means the manifest is usable.
    pub fn validate(&self, dir_name: &str) -> Vec<String> {
        let mut problems = Vec::new();
        if !is_valid_name(&self.name) {
            problems.push(format!(
                "name {:?} must be 1-{MAX_NAME_LEN} chars of a-z, 0-9, '-', '_' and start with a letter or digit",
                self.name
            ));
        }
        if self.name != dir_name {
            problems.push(format!(
                "name {:?} must match its folder name {dir_name:?}",
                self.name
            ));
        }
        if RESERVED_NAMES.contains(&self.name.as_str()) {
            problems.push(format!("name {:?} is reserved by toolbox", self.name));
        }
        if let Some(version) = &self.version
            && Version::parse(version).is_err()
        {
            problems.push(format!("version {version:?} must be semver like 1.2.0"));
        }
        if self.description.trim().is_empty() {
            problems.push("description must not be empty".to_string());
        }
        for (name, spec) in &self.args {
            problems.extend(validate_arg(name, spec));
        }
        for secret in &self.permissions.vault {
            if !is_valid_name(secret) {
                problems.push(format!("permissions.vault entry {secret:?} is not a valid secret name"));
            }
        }
        if self.permissions.http.iter().any(|h| h.trim().is_empty()) {
            problems.push("permissions.http must not contain empty hosts".to_string());
        }
        problems
    }
}

fn validate_arg(name: &str, spec: &ArgSpec) -> Vec<String> {
    let mut problems = Vec::new();
    if !is_valid_name(name) || name == "help" {
        problems.push(format!("arg {name:?} is not a valid arg name"));
    }
    if spec.kind == ArgType::Boolean && spec.required {
        problems.push(format!("arg {name:?}: boolean args are flags and cannot be required"));
    }
    if spec.required && spec.default.is_some() {
        problems.push(format!("arg {name:?}: a required arg cannot have a default"));
    }
    if let Some(default) = &spec.default
        && !default_matches(spec.kind, default)
    {
        problems.push(format!("arg {name:?}: default {default} is not a {:?}", spec.kind));
    }
    problems
}

fn default_matches(kind: ArgType, value: &Value) -> bool {
    match kind {
        ArgType::String => value.is_string(),
        ArgType::Integer => value.is_i64(),
        ArgType::Number => value.is_number(),
        ArgType::Boolean => value.is_boolean(),
    }
}

/// Names for commands, args and secrets: lowercase, digits, '-' and '_'.
pub fn is_valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    let starts_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    starts_ok
        && name.len() <= MAX_NAME_LEN
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"{
        "name": "pr-status",
        "description": "Show a PR",
        "args": {
            "repo": { "type": "string", "required": true },
            "limit": { "type": "integer", "default": 5 },
            "verbose": { "type": "boolean" }
        },
        "permissions": { "http": ["api.github.com"], "vault": ["github"] }
    }"#;

    #[test]
    fn parses_and_validates_a_good_manifest() {
        let manifest = Manifest::parse(VALID).unwrap();
        assert_eq!(manifest.args["repo"].kind, ArgType::String);
        assert_eq!(manifest.permissions.vault, vec!["github"]);
        assert!(manifest.validate("pr-status").is_empty());
    }

    #[test]
    fn rejects_unknown_fields() {
        let err = Manifest::parse(r#"{"name":"a","description":"b","nope":1}"#).unwrap_err();
        assert!(format!("{err:#}").contains("unknown field"));
    }

    #[test]
    fn reports_name_problems() {
        let manifest = Manifest::parse(r#"{"name":"self","description":"x"}"#).unwrap();
        let problems = manifest.validate("other");
        assert!(problems.iter().any(|p| p.contains("reserved")));
        assert!(problems.iter().any(|p| p.contains("folder name")));
    }

    #[test]
    fn reports_arg_problems() {
        let manifest = Manifest::parse(
            r#"{"name":"a","description":"x","args":{
                "flag": {"type":"boolean","required":true},
                "n": {"type":"integer","default":"five"},
                "Bad": {"type":"string"},
                "both": {"type":"string","required":true,"default":"x"}
            }}"#,
        )
        .unwrap();
        let problems = manifest.validate("a").join("\n");
        assert!(problems.contains("cannot be required"));
        assert!(problems.contains("is not a Integer"));
        assert!(problems.contains("\"Bad\" is not a valid arg name"));
        assert!(problems.contains("required arg cannot have a default"));
    }

    #[test]
    fn reports_bad_vault_names_and_empty_description() {
        let manifest = Manifest::parse(
            r#"{"name":"a","description":" ","permissions":{"vault":["Bad Name"],"http":[""]}}"#,
        )
        .unwrap();
        let problems = manifest.validate("a").join("\n");
        assert!(problems.contains("description must not be empty"));
        assert!(problems.contains("not a valid secret name"));
        assert!(problems.contains("empty hosts"));
    }

    #[test]
    fn version_must_be_semver() {
        let good = Manifest::parse(r#"{"name":"a","version":"1.2.0","description":"x"}"#).unwrap();
        assert!(good.validate("a").is_empty());
        assert_eq!(good.semver(), Some(Version::new(1, 2, 0)));

        let bad = Manifest::parse(r#"{"name":"a","version":"v1.2","description":"x"}"#).unwrap();
        assert!(bad.validate("a").join("\n").contains("must be semver"));
        assert_eq!(bad.semver(), None);
    }

    #[test]
    fn name_rules() {
        assert!(is_valid_name("gh-pr_2"));
        assert!(!is_valid_name(""));
        assert!(!is_valid_name("-x"));
        assert!(!is_valid_name("UPPER"));
        assert!(!is_valid_name(&"a".repeat(65)));
    }
}
