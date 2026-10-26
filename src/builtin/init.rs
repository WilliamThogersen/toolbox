use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Serialize;

pub const INSTRUCTIONS: &str = include_str!("../../docs/agent-instructions.md");

const CLAUDE_MD: &str = "CLAUDE.md";
const FILE_NAME: &str = "TOOLBOX.md";
const IMPORT: &str = "@TOOLBOX.md";
const MARKER: &str = "<!-- Written by `tb self init`.";
const PASTED_HEADING: &str = "## toolbox (tb)";

#[derive(Debug, Serialize)]
pub struct Installed {
    pub claude_md: String,
    pub instructions: String,
    pub imported: bool,
    pub updated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Serialize)]
#[expect(clippy::struct_field_names, reason = "the field names are the JSON `tb self init --remove` prints")]
pub struct Removed {
    pub claude_md: String,
    pub instructions: String,
    pub import_removed: bool,
    pub deleted: bool,
}

pub fn install(claude_dir: &Path) -> Result<Installed> {
    fs::create_dir_all(claude_dir).with_context(|| format!("could not create {}", claude_dir.display()))?;
    let file = claude_dir.join(FILE_NAME);
    let current = read_optional(&file)?;
    if let Some(text) = &current
        && !text.starts_with(MARKER)
    {
        bail!("{} exists and was not written by toolbox. Move it away, then run `tb self init` again", file.display());
    }
    let updated = current.as_deref() != Some(INSTRUCTIONS);
    if updated {
        fs::write(&file, INSTRUCTIONS).with_context(|| format!("could not write {}", file.display()))?;
    }

    let claude_md = claude_dir.join(CLAUDE_MD);
    let text = read_optional(&claude_md)?.unwrap_or_default();
    let imported = !has_import(&text);
    if imported {
        fs::write(&claude_md, with_import(&text)).with_context(|| format!("could not write {}", claude_md.display()))?;
    }
    let note = text.lines().any(|line| line.trim() == PASTED_HEADING).then(|| {
        format!("{} still has the `{PASTED_HEADING}` section pasted from the docs. Delete it: {FILE_NAME} replaces it.", claude_md.display())
    });
    Ok(Installed {
        claude_md: claude_md.display().to_string(),
        instructions: file.display().to_string(),
        imported,
        updated,
        note,
    })
}

pub fn remove(claude_dir: &Path) -> Result<Removed> {
    let claude_md = claude_dir.join(CLAUDE_MD);
    let text = read_optional(&claude_md)?.unwrap_or_default();
    let import_removed = has_import(&text);
    if import_removed {
        fs::write(&claude_md, without_import(&text)).with_context(|| format!("could not write {}", claude_md.display()))?;
    }

    let file = claude_dir.join(FILE_NAME);
    let deleted = read_optional(&file)?.is_some_and(|text| text.starts_with(MARKER));
    if deleted {
        fs::remove_file(&file).with_context(|| format!("could not delete {}", file.display()))?;
    }
    Ok(Removed {
        claude_md: claude_md.display().to_string(),
        instructions: file.display().to_string(),
        import_removed,
        deleted,
    })
}

fn read_optional(path: &Path) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("could not read {}", path.display())),
    }
}

fn has_import(text: &str) -> bool {
    text.lines().any(|line| line.trim() == IMPORT)
}

fn with_import(text: &str) -> String {
    let gap = match text {
        "" => "",
        _ if text.ends_with('\n') => "\n",
        _ => "\n\n",
    };
    format!("{text}{gap}{IMPORT}\n")
}

fn without_import(text: &str) -> String {
    let kept: Vec<&str> = text.lines().filter(|line| line.trim() != IMPORT).collect();
    let body = kept.join("\n");
    let body = body.trim_end();
    if body.is_empty() { String::new() } else { format!("{body}\n") }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_is_its_own_paragraph_and_removing_restores_the_text() {
        for (before, after, restored) in [
            ("", "@TOOLBOX.md\n", ""),
            ("# Mine\n", "# Mine\n\n@TOOLBOX.md\n", "# Mine\n"),
            ("# Mine", "# Mine\n\n@TOOLBOX.md\n", "# Mine\n"),
        ] {
            assert_eq!(with_import(before), after, "{before:?}");
            assert_eq!(without_import(after), restored, "{before:?}");
        }
        assert_eq!(without_import("a\n  @TOOLBOX.md  \nb\n"), "a\nb\n");
    }

    #[test]
    fn creates_both_files_when_nothing_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(".claude");
        let report = install(&dir).unwrap();
        assert!(report.imported && report.updated && report.note.is_none());
        assert_eq!(fs::read_to_string(dir.join(CLAUDE_MD)).unwrap(), "@TOOLBOX.md\n");
        assert_eq!(fs::read_to_string(dir.join(FILE_NAME)).unwrap(), INSTRUCTIONS);
    }

    #[test]
    fn refreshes_old_instructions_but_never_overwrites_the_users_file() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join(FILE_NAME);
        fs::write(&file, format!("{MARKER} old -->\nold text\n")).unwrap();
        assert!(install(tmp.path()).unwrap().updated);
        assert_eq!(fs::read_to_string(&file).unwrap(), INSTRUCTIONS);

        fs::write(&file, "my own notes\n").unwrap();
        let err = install(tmp.path()).unwrap_err().to_string();
        assert!(err.contains("not written by toolbox"), "{err}");
        let removed = remove(tmp.path()).unwrap();
        assert!(removed.import_removed && !removed.deleted);
        assert_eq!(fs::read_to_string(&file).unwrap(), "my own notes\n");
    }

    #[test]
    fn points_out_the_snippet_pasted_from_the_docs() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join(CLAUDE_MD), "## toolbox (tb)\n`tb` is my toolbox CLI.\n").unwrap();
        let note = install(tmp.path()).unwrap().note.unwrap();
        assert!(note.contains("Delete it"), "{note}");
    }

    #[test]
    fn instructions_carry_the_marker() {
        assert!(INSTRUCTIONS.starts_with(MARKER));
    }
}
