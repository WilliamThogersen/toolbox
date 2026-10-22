//! `tb self new <name>`: writes a working starter command.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use crate::manifest::{ArgSpec, ArgType, Manifest, Permissions, RESERVED_NAMES, is_valid_name};
use crate::registry::{MANIFEST_FILE, SCRIPT_FILE};

const FIRST_VERSION: &str = "0.1.0";

const SCRIPT_TEMPLATE: &str = r#"-- Receives the parsed args. Whatever you return is printed as JSON.
-- Run `tb self guide` for the full API: http, json, exec, env, vault, log.
return function(args)
  return { message = "hello " .. (args.name or "world") }
end
"#;

#[derive(Debug, Serialize)]
pub struct Created {
    pub dir: String,
    pub files: Vec<String>,
    pub next: String,
}

pub fn create(commands_dir: &Path, name: &str, description: &str) -> Result<Created> {
    ensure!(is_valid_name(name), "{name:?} is not a valid command name (a-z, 0-9, '-', '_')");
    ensure!(!RESERVED_NAMES.contains(&name), "{name:?} is reserved by toolbox");
    let dir = commands_dir.join(name);
    ensure!(!dir.exists(), "command {name:?} already exists at {}", dir.display());

    let manifest = Manifest {
        name: name.to_string(),
        version: Some(FIRST_VERSION.to_string()),
        description: description.to_string(),
        args: BTreeMap::from([(
            "name".to_string(),
            ArgSpec {
                kind: ArgType::String,
                required: false,
                description: "Who to greet".to_string(),
                default: None,
            },
        )]),
        permissions: Permissions::default(),
    };
    fs::create_dir_all(&dir).with_context(|| format!("could not create {}", dir.display()))?;
    let manifest_path = dir.join(MANIFEST_FILE);
    let script_path = dir.join(SCRIPT_FILE);
    fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)? + "\n")?;
    fs::write(&script_path, SCRIPT_TEMPLATE)?;

    Ok(Created {
        dir: dir.display().to_string(),
        files: vec![
            manifest_path.display().to_string(),
            script_path.display().to_string(),
        ],
        next: format!("Edit both files, run `tb self check`, then `tb {name} --name you`"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry;

    #[test]
    fn created_command_loads_cleanly() {
        let tmp = tempfile::tempdir().unwrap();
        create(tmp.path(), "hello", "Says hello").unwrap();
        let loaded = registry::load(tmp.path()).unwrap();
        assert!(loaded.problems.is_empty(), "{:?}", loaded.problems);
        assert_eq!(loaded.commands[0].manifest.description, "Says hello");
    }

    #[test]
    fn refuses_bad_reserved_or_existing_names() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(create(tmp.path(), "Bad", "x").is_err());
        assert!(create(tmp.path(), "self", "x").is_err());
        create(tmp.path(), "hello", "x").unwrap();
        assert!(create(tmp.path(), "hello", "x").is_err());
    }
}
