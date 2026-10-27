use std::collections::BTreeMap;

use anyhow::{Context, Result};
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::vault::names::{NAME_RULES, is_secret_pattern};

pub const RESERVED_NAMES: &[&str] = &["self", "help", "tb", "toolbox"];

const MAX_NAME_LEN: usize = 64;

pub const MAX_CPU_SECONDS: f64 = 24.0 * 60.0 * 60.0;
pub const MAX_MEMORY_MB: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub description: String,
    #[serde(default)]
    pub args: BTreeMap<String, ArgSpec>,
    #[serde(default)]
    pub permissions: Permissions,
    #[serde(default, skip_serializing_if = "Limits::is_default")]
    pub limits: Limits,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub subcommands: BTreeMap<String, Subcommand>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Subcommand {
    pub description: String,
    #[serde(default)]
    pub args: BTreeMap<String, ArgSpec>,
    #[serde(default)]
    pub permissions: Permissions,
    #[serde(default, skip_serializing_if = "Limits::is_default")]
    pub limits: Limits,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_seconds: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_mb: Option<u64>,
}

impl Limits {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    fn problems(&self) -> Vec<String> {
        let cpu = self
            .cpu_seconds
            .filter(|secs| !(*secs > 0.0 && *secs <= MAX_CPU_SECONDS))
            .map(|secs| format!("limits.cpu_seconds {secs} must be above 0 and at most {MAX_CPU_SECONDS}"));
        let memory = self
            .memory_mb
            .filter(|mb| !(1..=MAX_MEMORY_MB).contains(mb))
            .map(|mb| format!("limits.memory_mb {mb} must be between 1 and {MAX_MEMORY_MB}"));
        cpu.into_iter().chain(memory).collect()
    }
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

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Permissions {
    #[serde(default)]
    pub http: Vec<String>,
    #[serde(default)]
    pub vault: Vec<String>,
    #[serde(default)]
    pub exec: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(default)]
    pub write: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub terminal: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub background: bool,
}

#[expect(clippy::trivially_copy_pass_by_ref, reason = "serde's skip_serializing_if passes a reference")]
fn is_false(flag: &bool) -> bool {
    !flag
}

impl Manifest {
    pub fn parse(json: &str) -> Result<Self> {
        serde_json::from_str(json).context("invalid command.json")
    }

    pub fn semver(&self) -> Option<Version> {
        self.version.as_deref().and_then(|v| Version::parse(v).ok())
    }

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
        problems.extend(validate_spec("", &self.args, &self.permissions, &self.limits));
        problems.extend(self.subcommand_problems());
        problems
    }

    fn subcommand_problems(&self) -> Vec<String> {
        if self.subcommands.is_empty() {
            return Vec::new();
        }
        let at_top = !self.args.is_empty() || self.permissions != Permissions::default() || !self.limits.is_default();
        let top = at_top.then(|| {
            "a command with subcommands takes args, permissions and limits on each subcommand, not at the top".to_string()
        });
        let each = self.subcommands.iter().flat_map(|(name, sub)| {
            let at = format!("subcommands.{name}: ");
            let naming = (!is_valid_name(name) || name == "help").then(|| {
                format!("subcommand {name:?} must be 1-{MAX_NAME_LEN} chars of a-z, 0-9, '-', '_', start with a letter or digit and not be \"help\"")
            });
            let description = sub
                .description
                .trim()
                .is_empty()
                .then(|| format!("{at}description must not be empty"));
            naming
                .into_iter()
                .chain(description)
                .chain(validate_spec(&at, &sub.args, &sub.permissions, &sub.limits))
        });
        top.into_iter().chain(each).collect()
    }
}

fn validate_spec(at: &str, args: &BTreeMap<String, ArgSpec>, permissions: &Permissions, limits: &Limits) -> Vec<String> {
    let mut problems = Vec::new();
    for (name, spec) in args {
        problems.extend(validate_arg(name, spec));
    }
    for secret in &permissions.vault {
        if !is_secret_pattern(secret) {
            problems.push(format!(
                "permissions.vault entry {secret:?} is not a valid secret name or pattern ({NAME_RULES}, or github/* for any account)"
            ));
        }
    }
    if permissions.http.iter().any(|h| h.trim().is_empty()) {
        problems.push("permissions.http must not contain empty hosts".to_string());
    }
    for (kind, folders) in [("read", &permissions.read), ("write", &permissions.write)] {
        problems.extend(folders.iter().filter_map(|folder| validate_folder(kind, folder)));
    }
    problems.extend(limits.problems());
    problems.into_iter().map(|problem| format!("{at}{problem}")).collect()
}

fn validate_folder(kind: &str, folder: &str) -> Option<String> {
    if folder.trim().is_empty() {
        return Some(format!("permissions.{kind} must not contain empty paths"));
    }
    if folder.starts_with('~') && folder != "~" && !folder.starts_with("~/") {
        return Some(format!(
            "permissions.{kind} entry {folder:?}: only ~ and ~/... are supported, not ~user"
        ));
    }
    None
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
    fn vault_entries_may_be_folders_and_patterns() {
        let manifest = Manifest::parse(
            r#"{"name":"a","description":"x","permissions":{"vault":["stripe","github/work","github/*/token"]}}"#,
        )
        .unwrap();
        assert_eq!(manifest.validate("a"), Vec::<String>::new());
        let manifest = Manifest::parse(r#"{"name":"a","description":"x","permissions":{"vault":["*"]}}"#).unwrap();
        let problems = manifest.validate("a").join("\n");
        assert!(problems.contains("not a valid secret name or pattern"), "{problems}");
    }

    #[test]
    fn reports_bad_folders() {
        let manifest = Manifest::parse(
            r#"{"name":"a","description":"x","permissions":{"read":["~/notes", ".", ""],"write":["~bob/x"]}}"#,
        )
        .unwrap();
        let problems = manifest.validate("a").join("\n");
        assert!(problems.contains("permissions.read must not contain empty paths"), "{problems}");
        assert!(problems.contains("not ~user"), "{problems}");
        assert!(!problems.contains("~/notes"), "{problems}");
    }

    #[test]
    fn limits_are_optional_and_checked() {
        let none = Manifest::parse(r#"{"name":"a","description":"x"}"#).unwrap();
        assert_eq!(none.limits, Limits::default());
        assert!(!serde_json::to_string(&none).unwrap().contains("limits"));

        let more = Manifest::parse(r#"{"name":"a","description":"x","limits":{"cpu_seconds":300,"memory_mb":2048}}"#).unwrap();
        assert_eq!(more.limits, Limits { cpu_seconds: Some(300.0), memory_mb: Some(2048) });
        assert!(more.validate("a").is_empty());

        let bad = Manifest::parse(r#"{"name":"a","description":"x","limits":{"cpu_seconds":0,"memory_mb":0}}"#).unwrap();
        let problems = bad.validate("a").join("\n");
        assert!(problems.contains("limits.cpu_seconds 0 must be above 0"), "{problems}");
        assert!(problems.contains("limits.memory_mb 0 must be between 1"), "{problems}");
        let huge = Manifest::parse(r#"{"name":"a","description":"x","limits":{"cpu_seconds":1e9}}"#).unwrap();
        assert!(!huge.validate("a").is_empty());
        assert!(Manifest::parse(r#"{"name":"a","description":"x","limits":{"cpu":1}}"#).is_err());
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
