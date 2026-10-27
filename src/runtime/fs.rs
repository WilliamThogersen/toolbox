use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;

use anyhow::{Context, Result, anyhow, bail, ensure};
use mlua::{FromLuaMulti, IntoLuaMulti, Lua, LuaSerdeExt, LuaString};
use serde::Serialize;

use super::{lua_error, read_capped, ser_options};
use crate::command::manifest::Permissions;

#[derive(Debug, Clone, Copy)]
enum Access {
    Read,
    Write,
}

pub struct FsGuard {
    read: Vec<Root>,
    write: Vec<Root>,
}

struct Root {
    absolute: PathBuf,
    real: PathBuf,
}

#[derive(Debug, Serialize)]
struct Entry {
    name: String,
    #[serde(rename = "type")]
    kind: &'static str,
    size: u64,
}

impl FsGuard {
    pub fn new(perms: &Permissions) -> Self {
        let readable: Vec<String> = perms.read.iter().chain(&perms.write).cloned().collect();
        Self {
            read: resolved(&readable),
            write: resolved(&perms.write),
        }
    }

    fn roots(&self, access: Access) -> (&'static str, &[Root]) {
        match access {
            Access::Read => ("read", &self.read),
            Access::Write => ("write", &self.write),
        }
    }

    fn check(&self, raw: &str, access: Access) -> Result<PathBuf> {
        self.guarded(raw, access, real)
    }

    fn check_entry(&self, raw: &str, access: Access) -> Result<PathBuf> {
        self.guarded(raw, access, |path| {
            let (Some(name), Some(parent)) = (path.file_name(), path.parent()) else {
                bail!("{} does not name a file or folder", path.display());
            };
            Ok(real(parent)?.join(name))
        })
    }

    fn guarded(
        &self,
        raw: &str,
        access: Access,
        resolve: impl Fn(&Path) -> Result<PathBuf>,
    ) -> Result<PathBuf> {
        let (kind, roots) = self.roots(access);
        let denied =
            || anyhow!("{raw:?} is not inside a folder listed in this command's permissions.{kind}");
        if roots.is_empty() {
            return Err(denied());
        }
        let path = absolute(raw)?;
        match resolve(&path) {
            Ok(resolved) if roots.iter().any(|root| resolved.starts_with(&root.real)) => Ok(resolved),
            Err(e) if written_inside(&path, roots) => Err(e),
            _ => Err(denied()),
        }
    }

    fn read(&self, raw: &str) -> Result<Vec<u8>> {
        let path = self.check(raw, Access::Read)?;
        let meta = fs::metadata(&path).with_context(|| format!("could not read {raw:?}"))?;
        ensure!(meta.is_file(), "{raw:?} is not a file");
        let file = File::open(&path).with_context(|| format!("could not read {raw:?}"))?;
        read_capped(file, &format!("{raw:?}"))
    }

    fn write(&self, raw: &str, data: &[u8], append: bool) -> Result<()> {
        let path = self.check(raw, Access::Write)?;
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .append(append)
            .truncate(!append)
            .open(&path)
            .with_context(|| format!("could not write {raw:?}"))?;
        file.write_all(data)
            .with_context(|| format!("could not write {raw:?}"))
    }

    fn list(&self, raw: &str) -> Result<Vec<Entry>> {
        let path = self.check(raw, Access::Read)?;
        let mut entries = fs::read_dir(&path)
            .with_context(|| format!("could not list {raw:?}"))?
            .map(|item| {
                let item = item?;
                let meta = fs::symlink_metadata(item.path())?;
                Ok(Entry {
                    name: item.file_name().to_string_lossy().into_owned(),
                    kind: kind_of(&meta),
                    size: if meta.is_file() { meta.len() } else { 0 },
                })
            })
            .collect::<std::io::Result<Vec<_>>>()
            .with_context(|| format!("could not list {raw:?}"))?;
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    fn exists(&self, raw: &str) -> Result<bool> {
        let path = self
            .check(raw, Access::Read)
            .or_else(|_| self.check_entry(raw, Access::Read))?;
        Ok(fs::symlink_metadata(path).is_ok())
    }

    fn mkdir(&self, raw: &str) -> Result<()> {
        let path = self.check(raw, Access::Write)?;
        fs::create_dir_all(&path).with_context(|| format!("could not create {raw:?}"))
    }

    fn copy(&self, from: &str, to: &str) -> Result<()> {
        let source = self.check(from, Access::Read)?;
        let meta = fs::metadata(&source).with_context(|| format!("could not copy {from:?}"))?;
        ensure!(meta.is_file(), "{from:?} is not a file: fs.copy copies one file");
        let target = self.check(to, Access::Write)?;
        ensure!(!target.is_dir(), "{to:?} is a folder: name the file to copy to");
        let same = fs::metadata(&target).is_ok_and(|there| there.dev() == meta.dev() && there.ino() == meta.ino());
        ensure!(!same, "{from:?} and {to:?} are the same file");
        fs::copy(&source, &target).with_context(|| format!("could not copy {from:?} to {to:?}"))?;
        Ok(())
    }

    fn rename(&self, from: &str, to: &str) -> Result<()> {
        let source = self.movable(from, "moved")?;
        let target = self.check_entry(to, Access::Write)?;
        let (_, roots) = self.roots(Access::Write);
        let holds_root = |path: &Path| roots.iter().any(|root| root.real.starts_with(path));
        ensure!(
            !holds_root(&source) && !holds_root(&target),
            "fs.move can't move a folder that holds one listed in permissions.write, or put anything in a listed folder's place"
        );
        fs::rename(&source, &target).with_context(|| format!("could not move {from:?} to {to:?} (both must be on the same disk)"))
    }

    fn chmod(&self, raw: &str, mode: &str) -> Result<()> {
        let path = self.check(raw, Access::Write)?;
        let bits = u32::from_str_radix(mode, 8)
            .ok()
            .filter(|bits| (3..=4).contains(&mode.len()) && *bits <= 0o777)
            .ok_or_else(|| anyhow!("mode {mode:?} must be octal like \"755\" or \"0644\", without setuid, setgid or sticky bits"))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(bits)).with_context(|| format!("could not change the mode of {raw:?}"))
    }

    fn movable(&self, raw: &str, done: &str) -> Result<PathBuf> {
        let path = self.check_entry(raw, Access::Write)?;
        let (_, roots) = self.roots(Access::Write);
        ensure!(
            !roots.iter().any(|root| root.real == path),
            "{raw:?} is a folder listed in this command's permissions.write, so it can't be {done}"
        );
        Ok(path)
    }

    fn remove(&self, raw: &str) -> Result<()> {
        let path = self.movable(raw, "removed")?;
        let meta = fs::symlink_metadata(&path).with_context(|| format!("could not remove {raw:?}"))?;
        if meta.is_dir() {
            fs::remove_dir(&path)
                .with_context(|| format!("could not remove {raw:?} (only empty folders can be removed)"))
        } else {
            fs::remove_file(&path).with_context(|| format!("could not remove {raw:?}"))
        }
    }
}

fn resolved(folders: &[String]) -> Vec<Root> {
    folders
        .iter()
        .filter_map(|folder| {
            let absolute = absolute(folder).ok()?;
            let real = real(&absolute).ok()?;
            Some(Root { absolute, real })
        })
        .collect()
}

fn written_inside(path: &Path, roots: &[Root]) -> bool {
    !path.components().any(|c| c == Component::ParentDir)
        && roots
            .iter()
            .any(|root| path.starts_with(&root.absolute) || path.starts_with(&root.real))
}

fn kind_of(meta: &fs::Metadata) -> &'static str {
    let kind = meta.file_type();
    if kind.is_symlink() {
        "symlink"
    } else if kind.is_dir() {
        "dir"
    } else if kind.is_file() {
        "file"
    } else {
        "other"
    }
}

fn absolute(raw: &str) -> Result<PathBuf> {
    ensure!(!raw.is_empty(), "path must not be empty");
    let path = match raw.strip_prefix('~') {
        Some("") => home()?,
        Some(rest) if rest.starts_with('/') => home()?.join(&rest[1..]),
        _ => PathBuf::from(raw),
    };
    if path.is_absolute() {
        return Ok(path);
    }
    let cwd = std::env::current_dir().context("could not find the current folder")?;
    Ok(cwd.join(path))
}

fn home() -> Result<PathBuf> {
    dirs::home_dir().ok_or_else(|| anyhow!("could not find the home folder"))
}

fn real(path: &Path) -> Result<PathBuf> {
    let mut missing: Vec<&OsStr> = Vec::new();
    for existing in path.ancestors() {
        match fs::symlink_metadata(existing) {
            Ok(_) => {
                let base = existing
                    .canonicalize()
                    .with_context(|| format!("could not resolve {}", existing.display()))?;
                return Ok(missing.iter().rev().fold(base, |acc, name| acc.join(name)));
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("could not resolve {}", existing.display())),
        }
        let Some(name) = existing.file_name() else {
            bail!("could not resolve {}: `..` must follow a folder that exists", path.display());
        };
        missing.push(name);
    }
    bail!("could not resolve {}: no part of it exists", path.display())
}

pub fn install(lua: &Lua, guard: &Rc<FsGuard>) -> mlua::Result<()> {
    let table = lua.create_table()?;
    table.set(
        "read",
        bind(lua, guard, |lua, g, path: String| Ok(lua.create_string(g.read(&path)?)?))?,
    )?;
    table.set(
        "write",
        bind(lua, guard, |_, g, (path, data): (String, LuaString)| {
            g.write(&path, &data.as_bytes(), false)
        })?,
    )?;
    table.set(
        "append",
        bind(lua, guard, |_, g, (path, data): (String, LuaString)| {
            g.write(&path, &data.as_bytes(), true)
        })?,
    )?;
    table.set(
        "list",
        bind(lua, guard, |lua, g, path: String| {
            Ok(lua.to_value_with(&g.list(&path)?, ser_options())?)
        })?,
    )?;
    table.set("exists", bind(lua, guard, |_, g, path: String| g.exists(&path))?)?;
    table.set("mkdir", bind(lua, guard, |_, g, path: String| g.mkdir(&path))?)?;
    table.set("remove", bind(lua, guard, |_, g, path: String| g.remove(&path))?)?;
    table.set("copy", bind(lua, guard, |_, g, (from, to): (String, String)| g.copy(&from, &to))?)?;
    table.set("move", bind(lua, guard, |_, g, (from, to): (String, String)| g.rename(&from, &to))?)?;
    table.set("chmod", bind(lua, guard, |_, g, (path, mode): (String, String)| g.chmod(&path, &mode))?)?;
    lua.globals().set("fs", table)
}

fn bind<A, R>(
    lua: &Lua,
    guard: &Rc<FsGuard>,
    op: impl Fn(&Lua, &FsGuard, A) -> Result<R> + 'static,
) -> mlua::Result<mlua::Function>
where
    A: FromLuaMulti,
    R: IntoLuaMulti,
{
    let guard = Rc::clone(guard);
    lua.create_function(move |lua, args: A| op(lua, &guard, args).map_err(lua_error))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;
    use crate::runtime::sandbox::new_lua;

    struct Setup {
        dir: tempfile::TempDir,
        lua: Lua,
    }

    impl Setup {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            for sub in ["allowed", "readonly", "outside"] {
                fs::create_dir(dir.path().join(sub)).unwrap();
            }
            fs::write(dir.path().join("readonly/notes.txt"), "read me").unwrap();
            fs::write(dir.path().join("outside/secret.txt"), "private").unwrap();
            let path = |sub: &str| dir.path().join(sub).display().to_string();
            let perms = Permissions {
                read: vec![path("readonly")],
                write: vec![path("allowed")],
                ..Permissions::default()
            };
            let lua = new_lua().unwrap();
            install(&lua, &Rc::new(FsGuard::new(&perms))).unwrap();
            lua.globals().set("root", dir.path().display().to_string()).unwrap();
            Self { dir, lua }
        }

        fn path(&self, sub: &str) -> PathBuf {
            self.dir.path().join(sub)
        }

        fn eval<T: mlua::FromLua>(&self, code: &str) -> T {
            self.lua.load(code).eval().unwrap()
        }

        fn err(&self, code: &str) -> String {
            self.lua.load(code).exec().unwrap_err().to_string()
        }
    }

    #[test]
    fn reads_and_writes_inside_allowed_folders() {
        let s = Setup::new();
        let text: String = s.eval(r#"return fs.read(root .. "/readonly/notes.txt")"#);
        assert_eq!(text, "read me");

        s.lua
            .load(r#"
                fs.mkdir(root .. "/allowed/sub/deeper")
                fs.write(root .. "/allowed/sub/out.txt", "one")
                fs.append(root .. "/allowed/sub/out.txt", " two")
            "#)
            .exec()
            .unwrap();
        assert_eq!(fs::read_to_string(s.path("allowed/sub/out.txt")).unwrap(), "one two");
        let back: String = s.eval(r#"return fs.read(root .. "/allowed/sub/out.txt")"#);
        assert_eq!(back, "one two");
    }

    #[test]
    fn copies_moves_and_changes_modes_inside_allowed_folders() {
        let s = Setup::new();
        s.lua
            .load(r#"
                fs.copy(root .. "/readonly/notes.txt", root .. "/allowed/copy.txt")
                fs.move(root .. "/allowed/copy.txt", root .. "/allowed/moved.txt")
                fs.chmod(root .. "/allowed/moved.txt", "750")
            "#)
            .exec()
            .unwrap();
        assert!(!s.path("allowed/copy.txt").exists());
        assert_eq!(fs::read_to_string(s.path("allowed/moved.txt")).unwrap(), "read me");
        assert_eq!(fs::metadata(s.path("allowed/moved.txt")).unwrap().permissions().mode() & 0o7777, 0o750);

        for (code, says) in [
            (r#"fs.copy(root .. "/outside/secret.txt", root .. "/allowed/x")"#, "permissions.read"),
            (r#"fs.copy(root .. "/readonly/notes.txt", root .. "/readonly/x")"#, "permissions.write"),
            (r#"fs.copy(root .. "/readonly", root .. "/allowed/x")"#, "fs.copy copies one file"),
            (r#"fs.copy(root .. "/readonly/notes.txt", root .. "/allowed")"#, "is a folder"),
            (r#"fs.move(root .. "/readonly/notes.txt", root .. "/allowed/x")"#, "permissions.write"),
            (r#"fs.move(root .. "/allowed/moved.txt", root .. "/outside/x")"#, "permissions.write"),
            (r#"fs.move(root .. "/allowed", root .. "/allowed2")"#, "can't be moved"),
            (r#"fs.chmod(root .. "/readonly/notes.txt", "644")"#, "permissions.write"),
            (r#"fs.chmod(root .. "/allowed/moved.txt", "4755")"#, "without setuid"),
            (r#"fs.chmod(root .. "/allowed/moved.txt", "rwx")"#, "must be octal"),
            (r#"fs.chmod(root .. "/allowed/moved.txt", "7")"#, "must be octal"),
        ] {
            let err = s.err(code);
            assert!(err.contains(says), "{code}: {err}");
        }
        assert_eq!(fs::read_to_string(s.path("outside/secret.txt")).unwrap(), "private");
    }

    #[test]
    fn a_move_cannot_turn_an_allowed_folder_into_a_link_elsewhere() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        for sub in ["proj", "outside", "cache"] {
            fs::create_dir(root.join(sub)).unwrap();
        }
        fs::write(root.join("outside/secret.txt"), "private").unwrap();
        symlink("../outside", root.join("proj/link")).unwrap();
        let perms = Permissions {
            write: vec![root.join("proj").display().to_string(), root.join("cache/tool").display().to_string()],
            ..Permissions::default()
        };
        let lua = new_lua().unwrap();
        install(&lua, &Rc::new(FsGuard::new(&perms))).unwrap();
        lua.globals().set("root", root.display().to_string()).unwrap();

        let err = lua.load(r#"fs.move(root .. "/proj/link", root .. "/cache/tool")"#).exec().unwrap_err().to_string();
        assert!(err.contains("in a listed folder's place"), "{err}");
        symlink("../outside", root.join("cache/tool")).unwrap();
        let err = lua.load(r#"return fs.read(root .. "/cache/tool/secret.txt")"#).exec().unwrap_err().to_string();
        assert!(err.contains("permissions.read"), "an allowed folder swapped for a link mid-run still counts: {err}");
    }

    #[test]
    fn copying_a_file_onto_itself_keeps_it() {
        let s = Setup::new();
        fs::write(s.path("allowed/a.txt"), "keep").unwrap();
        let err = s.err(r#"fs.copy(root .. "/allowed/a.txt", root .. "/allowed/./a.txt")"#);
        assert!(err.contains("are the same file"), "{err}");
        assert_eq!(fs::read_to_string(s.path("allowed/a.txt")).unwrap(), "keep");
    }

    #[test]
    fn lists_exists_and_removes() {
        let s = Setup::new();
        fs::write(s.path("allowed/b.txt"), "12345").unwrap();
        fs::create_dir(s.path("allowed/a")).unwrap();
        let listed: String = s.eval(
            r#"
            local parts = {}
            for _, e in ipairs(fs.list(root .. "/allowed")) do
              parts[#parts + 1] = e.name .. ":" .. e.type .. ":" .. e.size
            end
            return table.concat(parts, ",")
        "#,
        );
        assert_eq!(listed, "a:dir:0,b.txt:file:5");

        assert!(s.eval::<bool>(r#"return fs.exists(root .. "/allowed/b.txt")"#));
        assert!(!s.eval::<bool>(r#"return fs.exists(root .. "/allowed/nope.txt")"#));
        s.lua
            .load(r#"fs.remove(root .. "/allowed/b.txt") fs.remove(root .. "/allowed/a")"#)
            .exec()
            .unwrap();
        assert!(!s.path("allowed/b.txt").exists() && !s.path("allowed/a").exists());

        fs::create_dir_all(s.path("allowed/full/x")).unwrap();
        assert!(s.err(r#"fs.remove(root .. "/allowed/full")"#).contains("only empty folders"));
    }

    #[test]
    fn refuses_paths_outside_the_permissions() {
        let s = Setup::new();
        assert!(s.err(r#"fs.read(root .. "/outside/secret.txt")"#).contains("permissions.read"));
        assert!(s.err(r#"fs.read(root .. "/allowed/../outside/secret.txt")"#).contains("permissions.read"));
        assert!(s.err(r#"fs.write(root .. "/readonly/notes.txt", "x")"#).contains("permissions.write"));
        assert!(s.err(r"fs.list(root)").contains("permissions.read"));
        assert!(s.err(r#"fs.exists("/etc/passwd")"#).contains("permissions.read"));
        assert!(s.err(r#"fs.remove(root .. "/readonly/notes.txt")"#).contains("permissions.write"));
        assert!(s.err(r#"fs.write(root .. "/allowed/missing/../../outside/x", "x")"#).contains("permissions.write"));
        assert_eq!(fs::read_to_string(s.path("readonly/notes.txt")).unwrap(), "read me");
    }

    #[test]
    fn symlinks_cannot_escape() {
        let s = Setup::new();
        symlink(s.path("outside"), s.path("allowed/link-dir")).unwrap();
        symlink(s.path("outside/secret.txt"), s.path("allowed/link-file")).unwrap();
        symlink(s.path("outside/new.txt"), s.path("allowed/dangling")).unwrap();

        assert!(s.err(r#"fs.read(root .. "/allowed/link-file")"#).contains("permissions.read"));
        assert!(s.err(r#"fs.read(root .. "/allowed/link-dir/secret.txt")"#).contains("permissions.read"));
        assert!(s.err(r#"fs.write(root .. "/allowed/link-dir/new.txt", "x")"#).contains("permissions.write"));
        assert!(s.err(r#"fs.write(root .. "/allowed/dangling", "x")"#).contains("could not resolve"));
        assert!(!s.path("outside/new.txt").exists());

        assert!(s.eval::<bool>(r#"return fs.exists(root .. "/allowed/dangling")"#));

        s.lua.load(r#"fs.remove(root .. "/allowed/link-file")"#).exec().unwrap();
        assert!(s.path("outside/secret.txt").exists());
    }

    #[test]
    fn named_pipes_are_refused_without_waiting_for_a_writer() {
        let s = Setup::new();
        let made = std::process::Command::new("mkfifo").arg(s.path("readonly/pipe")).status().unwrap();
        assert!(made.success());
        let err = s.err(r#"fs.read(root .. "/readonly/pipe")"#);
        assert!(err.contains("is not a file"), "{err}");
    }

    #[test]
    fn errors_outside_the_folders_do_not_reveal_what_exists() {
        let s = Setup::new();
        for path in ["/outside/secret.txt/x", "/nope/../x", "/outside/missing.txt", "/allowed/../outside/secret.txt/x"] {
            let err = s.err(&format!(r#"fs.exists(root .. "{path}")"#));
            assert!(err.contains("is not inside a folder listed"), "{path}: {err}");
        }
        fs::write(s.path("allowed/file"), "x").unwrap();
        let inside = s.err(r#"fs.write(root .. "/allowed/file/x", "y")"#);
        assert!(inside.contains("could not"), "{inside}");

        let none = new_lua().unwrap();
        install(&none, &Rc::new(FsGuard::new(&Permissions::default()))).unwrap();
        let err = none.load(r#"fs.exists("/etc/passwd/x")"#).exec().unwrap_err().to_string();
        assert!(err.contains("permissions.read"), "{err}");
    }

    #[test]
    fn allowed_folders_themselves_cannot_be_removed() {
        let s = Setup::new();
        for path in ["/allowed", "/allowed/."] {
            let err = s.err(&format!(r#"fs.remove(root .. "{path}")"#));
            assert!(err.contains("can't be removed"), "{path}: {err}");
        }
        assert!(s.path("allowed").is_dir());
    }

    #[test]
    fn relative_and_home_paths_resolve() {
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(absolute("x/y").unwrap(), cwd.join("x/y"));
        let home = dirs::home_dir().unwrap();
        assert_eq!(absolute("~").unwrap(), home);
        assert_eq!(absolute("~/notes").unwrap(), home.join("notes"));
        assert!(absolute("").is_err());
    }
}
