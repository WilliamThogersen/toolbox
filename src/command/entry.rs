use std::collections::BTreeMap;

use crate::command::manifest::{ArgSpec, Limits, Manifest, Permissions};
use crate::command::registry::SCRIPT_FILE;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Entry<'a> {
    pub command: &'a str,
    pub subcommand: Option<&'a str>,
    pub description: &'a str,
    pub args: &'a BTreeMap<String, ArgSpec>,
    pub permissions: &'a Permissions,
    pub limits: &'a Limits,
}

impl Entry<'_> {
    pub fn script(&self) -> String {
        self.subcommand
            .map_or_else(|| SCRIPT_FILE.to_string(), |sub| format!("{sub}.lua"))
    }

    pub fn label(&self) -> String {
        self.subcommand
            .map_or_else(|| self.command.to_string(), |sub| format!("{} {sub}", self.command))
    }
}

impl Manifest {
    pub fn is_group(&self) -> bool {
        !self.subcommands.is_empty()
    }

    pub fn entries(&self) -> Vec<Entry<'_>> {
        if !self.is_group() {
            return vec![Entry {
                command: &self.name,
                subcommand: None,
                description: &self.description,
                args: &self.args,
                permissions: &self.permissions,
                limits: &self.limits,
            }];
        }
        self.subcommands
            .iter()
            .map(|(name, sub)| Entry {
                command: &self.name,
                subcommand: Some(name),
                description: &sub.description,
                args: &sub.args,
                permissions: &sub.permissions,
                limits: &sub.limits,
            })
            .collect()
    }

    pub fn entry(&self, subcommand: Option<&str>) -> Option<Entry<'_>> {
        self.entries().into_iter().find(|entry| entry.subcommand == subcommand)
    }

    pub fn scripts(&self) -> Vec<String> {
        self.entries().iter().map(Entry::script).collect()
    }

    pub fn all_permissions(&self) -> Permissions {
        self.entries().iter().fold(Permissions::default(), |all, entry| {
            let merge = |have: Vec<String>, more: &[String]| {
                let new = more.iter().filter(|item| !have.contains(item)).cloned().collect::<Vec<_>>();
                [have, new].concat()
            };
            let perms = entry.permissions;
            Permissions {
                http: merge(all.http, &perms.http),
                vault: merge(all.vault, &perms.vault),
                exec: merge(all.exec, &perms.exec),
                env: merge(all.env, &perms.env),
                read: merge(all.read, &perms.read),
                write: merge(all.write, &perms.write),
                terminal: all.terminal || perms.terminal,
                background: all.background || perms.background,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GROUP: &str = r#"{
        "name": "notes",
        "description": "Keeps notes",
        "subcommands": {
            "add": { "description": "Adds a note", "permissions": { "write": ["~/notes"], "exec": ["git"], "terminal": true } },
            "sync": { "description": "Pushes notes", "permissions": { "exec": ["git"], "http": ["api.github.com"], "vault": ["github"] } }
        }
    }"#;

    #[test]
    fn a_plain_command_is_one_entry_running_run_lua() {
        let manifest = Manifest::parse(r#"{"name":"hello","description":"hi","permissions":{"exec":["git"]}}"#).unwrap();
        assert!(!manifest.is_group());
        let entries = manifest.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!((entries[0].script(), entries[0].label()), ("run.lua".to_string(), "hello".to_string()));
        assert_eq!(manifest.entry(None), Some(entries[0]));
        assert_eq!(manifest.entry(Some("hello")), None);
        assert_eq!(manifest.all_permissions(), manifest.permissions);
    }

    #[test]
    fn a_group_has_one_entry_and_script_per_subcommand() {
        let manifest = Manifest::parse(GROUP).unwrap();
        assert!(manifest.is_group());
        assert!(manifest.validate("notes").is_empty(), "{:?}", manifest.validate("notes"));
        assert_eq!(manifest.scripts(), vec!["add.lua", "sync.lua"]);
        let sync = manifest.entry(Some("sync")).unwrap();
        assert_eq!((sync.label(), sync.description), ("notes sync".to_string(), "Pushes notes"));
        assert_eq!(sync.permissions.vault, vec!["github"]);
        assert_eq!(manifest.entry(None), None);

        let all = manifest.all_permissions();
        assert!(all.terminal && !all.background);
        assert_eq!(all.exec, vec!["git"]);
        assert_eq!((all.write, all.http, all.vault), (vec!["~/notes".to_string()], vec!["api.github.com".to_string()], vec!["github".to_string()]));
    }

    #[test]
    fn group_problems_name_the_subcommand() {
        let manifest = Manifest::parse(
            r#"{"name":"notes","description":"x","permissions":{"exec":["git"]},"subcommands":{
                "help": {"description":"x"},
                "Bad": {"description":"x"},
                "add": {"description":" ","args":{"flag":{"type":"boolean","required":true}},"permissions":{"vault":["Bad Name"]},"limits":{"cpu_seconds":0}}
            }}"#,
        )
        .unwrap();
        let problems = manifest.validate("notes").join("\n");
        assert!(problems.contains("with subcommands takes args, permissions and limits on each subcommand"), "{problems}");
        assert!(problems.contains("subcommand \"help\" must be"), "{problems}");
        assert!(problems.contains("subcommand \"Bad\" must be"), "{problems}");
        assert!(problems.contains("subcommands.add: description must not be empty"), "{problems}");
        assert!(problems.contains("subcommands.add: arg \"flag\": boolean args are flags"), "{problems}");
        assert!(problems.contains("subcommands.add: permissions.vault entry \"Bad Name\""), "{problems}");
        assert!(problems.contains("subcommands.add: limits.cpu_seconds 0"), "{problems}");
        assert!(Manifest::parse(r#"{"name":"a","description":"x","subcommands":{"b":{"description":"x","nope":1}}}"#).is_err());
    }
}
