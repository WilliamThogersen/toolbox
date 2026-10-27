use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};

use crate::command::manifest::{Manifest, is_valid_name};
use crate::command::origin::read_plain;
use crate::command::registry::{CommandDef, SCRIPT_FILE};
use crate::vault::approval;

pub const LIB_DIR: &str = "lib";
pub const MAX_FILES: usize = 256;
pub const MAX_TOTAL_BYTES: u64 = 20 << 20;

#[derive(Debug, Clone, PartialEq)]
pub struct Sources {
    files: BTreeMap<String, String>,
}

impl Sources {
    pub fn read(def: &CommandDef) -> Result<Self> {
        Self::read_in(&def.dir, &def.manifest)
    }

    pub fn read_in(dir: &Path, manifest: &Manifest) -> Result<Self> {
        if let Some(bad) = manifest.subcommands.keys().find(|name| !is_valid_name(name)) {
            bail!("subcommand {bad:?} is not a valid name, so {} has no script for it", dir.display());
        }
        let paths: Vec<String> = manifest.scripts().into_iter().chain(lib_paths(dir)?).collect();
        ensure!(paths.len() <= MAX_FILES, "{} has more than {MAX_FILES} Lua files", dir.display());
        let mut total = 0;
        let mut files = BTreeMap::new();
        for path in paths {
            let text = read_plain(&dir.join(&path), MAX_TOTAL_BYTES)?.with_context(|| format!("missing {path}"))?;
            total += text.len() as u64;
            ensure!(
                total <= MAX_TOTAL_BYTES,
                "the Lua files in {} are larger than {} MB in all",
                dir.display(),
                MAX_TOTAL_BYTES >> 20
            );
            files.insert(path, text);
        }
        Ok(Self { files })
    }

    pub fn get(&self, path: &str) -> Option<&str> {
        self.files.get(path).map(String::as_str)
    }

    pub fn files(&self) -> impl Iterator<Item = (&str, &str)> {
        self.files.iter().map(|(path, text)| (path.as_str(), text.as_str()))
    }

    pub fn paths(&self) -> Vec<&str> {
        self.files.keys().map(String::as_str).collect()
    }

    pub fn fingerprint(&self, manifest_source: &str) -> String {
        match (self.files.len(), self.get(SCRIPT_FILE)) {
            (1, Some(script)) => approval::fingerprint(manifest_source, script),
            _ => approval::files_fingerprint(manifest_source, self.files()),
        }
    }
}

pub fn lib_path(module: &str) -> Option<String> {
    is_valid_name(module).then(|| format!("{LIB_DIR}/{module}.lua"))
}

fn lib_paths(dir: &Path) -> Result<Vec<String>> {
    let lib = dir.join(LIB_DIR);
    let kind = match lib.symlink_metadata() {
        Ok(meta) => meta.file_type(),
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err).with_context(|| format!("could not read {}", lib.display())),
    };
    ensure!(kind.is_dir(), "{} must be a folder, not a link or a file", lib.display());
    let mut paths: Vec<String> = fs::read_dir(&lib)
        .with_context(|| format!("could not read {}", lib.display()))?
        .filter_map(std::result::Result::ok)
        .filter_map(|item| item.file_name().to_str()?.strip_suffix(".lua").and_then(lib_path))
        .take(MAX_FILES + 1)
        .collect();
    paths.sort();
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, files: &[(&str, &str)]) {
        for (path, text) in files {
            let file = dir.join(path);
            fs::create_dir_all(file.parent().unwrap()).unwrap();
            fs::write(file, text).unwrap();
        }
    }

    fn group() -> Manifest {
        Manifest::parse(r#"{"name":"notes","description":"x","subcommands":{"add":{"description":"x"},"list":{"description":"x"}}}"#).unwrap()
    }

    #[test]
    fn a_plain_command_keeps_the_two_file_fingerprint() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), &[("run.lua", "return function() end"), ("notes.txt", "ignored")]);
        let manifest = Manifest::parse(r#"{"name":"hello","description":"x"}"#).unwrap();
        let sources = Sources::read_in(tmp.path(), &manifest).unwrap();
        assert_eq!(sources.paths(), vec!["run.lua"]);
        assert_eq!(sources.fingerprint("{}"), approval::fingerprint("{}", "return function() end"));
    }

    #[test]
    fn a_group_reads_each_subcommand_script_and_its_lib_files() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            &[
                ("add.lua", "return function() end"),
                ("list.lua", "return function() end"),
                ("helper.lua", "not a script of this group"),
                ("lib/store.lua", "return {}"),
                ("lib/Upper.lua", "not a module name"),
                ("lib/readme.md", "not Lua"),
                ("lib/deep/more.lua", "too deep"),
            ],
        );
        let sources = Sources::read_in(tmp.path(), &group()).unwrap();
        assert_eq!(sources.paths(), vec!["add.lua", "lib/store.lua", "list.lua"]);
        assert_eq!(sources.get("lib/store.lua"), Some("return {}"));
        assert_ne!(sources.fingerprint("{}"), approval::fingerprint("{}", "return function() end"));
    }

    #[test]
    fn the_fingerprint_changes_with_any_file_its_path_or_a_new_one() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), &[("add.lua", "a"), ("list.lua", "b"), ("lib/store.lua", "c")]);
        let fingerprint = || Sources::read_in(tmp.path(), &group()).unwrap().fingerprint("{}");
        let base = fingerprint();
        assert_eq!(base, fingerprint());

        write(tmp.path(), &[("lib/store.lua", "c ")]);
        let edited = fingerprint();
        assert_ne!(base, edited);

        fs::rename(tmp.path().join("lib/store.lua"), tmp.path().join("lib/kept.lua")).unwrap();
        let moved = fingerprint();
        assert_ne!(edited, moved);

        write(tmp.path(), &[("lib/extra.lua", "")]);
        assert_ne!(moved, fingerprint());
    }

    #[test]
    fn missing_scripts_links_and_oversized_files_are_errors() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), &[("add.lua", "a")]);
        let err = Sources::read_in(tmp.path(), &group()).unwrap_err();
        assert!(format!("{err:#}").contains("missing list.lua"), "{err:#}");

        write(tmp.path(), &[("list.lua", "b"), ("elsewhere.lua", "secret")]);
        fs::create_dir_all(tmp.path().join("lib")).unwrap();
        std::os::unix::fs::symlink(tmp.path().join("elsewhere.lua"), tmp.path().join("lib/linked.lua")).unwrap();
        assert!(Sources::read_in(tmp.path(), &group()).is_err());

        fs::remove_file(tmp.path().join("lib/linked.lua")).unwrap();
        fs::remove_dir(tmp.path().join("lib")).unwrap();
        std::os::unix::fs::symlink(tmp.path(), tmp.path().join("lib")).unwrap();
        let err = Sources::read_in(tmp.path(), &group()).unwrap_err();
        assert!(format!("{err:#}").contains("must be a folder"), "{err:#}");

        fs::remove_file(tmp.path().join("lib")).unwrap();
        let big = "x".repeat(usize::try_from(MAX_TOTAL_BYTES / 2 + 1).unwrap());
        write(tmp.path(), &[("add.lua", &big), ("list.lua", &big)]);
        let err = Sources::read_in(tmp.path(), &group()).unwrap_err();
        assert!(format!("{err:#}").contains("larger than 20 MB in all"), "{err:#}");
    }

    #[test]
    fn a_subcommand_name_cannot_reach_outside_the_folder() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("cmd");
        write(tmp.path(), &[("outside.lua", "not this command's"), ("cmd/x.lua", "")]);
        for bad in ["../outside", "/etc/hosts", "x.y"] {
            let source = serde_json::json!({ "name": "cmd", "description": "x", "subcommands": { bad: { "description": "x" } } });
            let manifest = Manifest::parse(&source.to_string()).unwrap();
            let err = Sources::read_in(&dir, &manifest).unwrap_err();
            assert!(format!("{err:#}").contains("is not a valid name"), "{bad}: {err:#}");
        }
    }

    #[test]
    fn module_names_follow_command_name_rules() {
        assert_eq!(lib_path("store"), Some("lib/store.lua".to_string()));
        for bad in ["", "../x", "a/b", "a.b", "Upper", "x.lua"] {
            assert_eq!(lib_path(bad), None, "{bad}");
        }
    }
}
