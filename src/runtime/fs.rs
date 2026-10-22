//! `fs.*` for scripts: files inside the folders listed in `permissions.read` and
//! `permissions.write`. Paths are checked after symlinks are resolved, so a link
//! inside an allowed folder can't reach outside it.

use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;

use anyhow::{Context, Result, anyhow, bail, ensure};
use mlua::{FromLuaMulti, IntoLuaMulti, Lua, LuaSerdeExt, LuaString};
use serde::Serialize;

use super::{lua_error, ser_options};
use crate::manifest::Permissions;

const MAX_READ_BYTES: u64 = 20 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
enum Access {
    Read,
    Write,
}

pub struct FsGuard {
    read: Vec<String>,
    write: Vec<String>,
}

/// An allowed folder, as written (made absolute) and with symlinks resolved.
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
        Self {
            // A folder a command may write to, it may also read.
            read: perms.read.iter().chain(&perms.write).cloned().collect(),
            write: perms.write.clone(),
        }
    }

    fn roots(&self, access: Access) -> (&'static str, Vec<Root>) {
        let (kind, folders) = match access {
            Access::Read => ("read", &self.read),
            Access::Write => ("write", &self.write),
        };
        // A folder that can't be resolved (say, a broken symlink) allows nothing.
        let roots = folders
            .iter()
            .filter_map(|folder| {
                let absolute = absolute(folder).ok()?;
                let real = real(&absolute).ok()?;
                Some(Root { absolute, real })
            })
            .collect();
        (kind, roots)
    }

    /// The real location of `raw`, if it is inside a folder allowed for `access`.
    fn check(&self, raw: &str, access: Access) -> Result<PathBuf> {
        self.guarded(raw, access, real)
    }

    /// Like `check`, but a symlink at `raw` is the entry itself, not where it points.
    fn check_entry(&self, raw: &str, access: Access) -> Result<PathBuf> {
        self.guarded(raw, access, |path| {
            let (Some(name), Some(parent)) = (path.file_name(), path.parent()) else {
                bail!("{} does not name a file or folder", path.display());
            };
            Ok(real(parent)?.join(name))
        })
    }

    /// Resolves `raw` and allows it only inside a folder listed for `access`. A path
    /// outside them gets the same denial whether it resolves or not, so error
    /// messages can't tell a script which files exist there.
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
            Err(e) if written_inside(&path, &roots) => Err(e),
            _ => Err(denied()),
        }
    }

    fn read(&self, raw: &str) -> Result<Vec<u8>> {
        let path = self.check(raw, Access::Read)?;
        let meta = fs::metadata(&path).with_context(|| format!("could not read {raw:?}"))?;
        ensure!(meta.is_file(), "{raw:?} is not a file");
        ensure!(
            meta.len() <= MAX_READ_BYTES,
            "{raw:?} is larger than {} MB",
            MAX_READ_BYTES / 1024 / 1024
        );
        fs::read(&path).with_context(|| format!("could not read {raw:?}"))
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
        // A broken symlink can't be resolved, but the link itself exists.
        let path = self
            .check(raw, Access::Read)
            .or_else(|_| self.check_entry(raw, Access::Read))?;
        Ok(fs::symlink_metadata(path).is_ok())
    }

    fn mkdir(&self, raw: &str) -> Result<()> {
        let path = self.check(raw, Access::Write)?;
        fs::create_dir_all(&path).with_context(|| format!("could not create {raw:?}"))
    }

    /// Removes a file, a symlink (not its target) or an empty folder.
    fn remove(&self, raw: &str) -> Result<()> {
        let path = self.check_entry(raw, Access::Write)?;
        let (_, roots) = self.roots(Access::Write);
        ensure!(
            !roots.iter().any(|root| root.real == path),
            "{raw:?} is a folder listed in this command's permissions.write, so it can't be removed"
        );
        let meta = fs::symlink_metadata(&path).with_context(|| format!("could not remove {raw:?}"))?;
        if meta.is_dir() {
            fs::remove_dir(&path)
                .with_context(|| format!("could not remove {raw:?} (only empty folders can be removed)"))
        } else {
            fs::remove_file(&path).with_context(|| format!("could not remove {raw:?}"))
        }
    }
}

/// Whether `path`, as written, sits in an allowed folder. It only decides if a
/// resolve error may be shown, so `..` (which could point anywhere) never counts.
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

/// `~` is the home folder. Relative paths start at the current folder.
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

/// Resolves symlinks in the part of `path` that exists. The missing rest is
/// appended as is. It can't hold `..`, so it can't climb out of the resolved part.
fn real(path: &Path) -> Result<PathBuf> {
    let mut existing = path;
    let mut missing: Vec<&OsStr> = Vec::new();
    loop {
        match fs::symlink_metadata(existing) {
            Ok(_) => break,
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("could not resolve {}", existing.display())),
        }
        let (Some(name), Some(parent)) = (existing.file_name(), existing.parent()) else {
            bail!("could not resolve {}: `..` must follow a folder that exists", path.display());
        };
        missing.push(name);
        existing = parent;
    }
    let base = existing
        .canonicalize()
        .with_context(|| format!("could not resolve {}", existing.display()))?;
    Ok(missing.iter().rev().fold(base, |acc, name| acc.join(name)))
}

pub fn install(lua: &Lua, guard: Rc<FsGuard>) -> mlua::Result<()> {
    let table = lua.create_table()?;
    table.set(
        "read",
        bind(lua, &guard, |lua, g, path: String| Ok(lua.create_string(g.read(&path)?)?))?,
    )?;
    table.set(
        "write",
        bind(lua, &guard, |_, g, (path, data): (String, LuaString)| {
            g.write(&path, &data.as_bytes(), false)
        })?,
    )?;
    table.set(
        "append",
        bind(lua, &guard, |_, g, (path, data): (String, LuaString)| {
            g.write(&path, &data.as_bytes(), true)
        })?,
    )?;
    table.set(
        "list",
        bind(lua, &guard, |lua, g, path: String| {
            Ok(lua.to_value_with(&g.list(&path)?, ser_options())?)
        })?,
    )?;
    table.set("exists", bind(lua, &guard, |_, g, path: String| g.exists(&path))?)?;
    table.set("mkdir", bind(lua, &guard, |_, g, path: String| g.mkdir(&path))?)?;
    table.set("remove", bind(lua, &guard, |_, g, path: String| g.remove(&path))?)?;
    lua.globals().set("fs", table)
}

/// A Lua function that calls `op` with the guard and turns its error into a Lua error.
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

    /// A sandbox folder with `allowed/` (read+write), `readonly/` and `outside/`.
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
            install(&lua, Rc::new(FsGuard::new(&perms))).unwrap();
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
        assert!(s.err(r#"fs.list(root)"#).contains("permissions.read"));
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

        // Removing a link removes the link, never its target.
        s.lua.load(r#"fs.remove(root .. "/allowed/link-file")"#).exec().unwrap();
        assert!(s.path("outside/secret.txt").exists());
    }

    #[test]
    fn errors_outside_the_folders_do_not_reveal_what_exists() {
        let s = Setup::new();
        // A file used as a folder, a missing folder before `..`, a missing file: one answer.
        for path in ["/outside/secret.txt/x", "/nope/../x", "/outside/missing.txt", "/allowed/../outside/secret.txt/x"] {
            let err = s.err(&format!(r#"fs.exists(root .. "{path}")"#));
            assert!(err.contains("is not inside a folder listed"), "{path}: {err}");
        }
        // Inside an allowed folder the real reason is useful and reveals nothing new.
        fs::write(s.path("allowed/file"), "x").unwrap();
        let inside = s.err(r#"fs.write(root .. "/allowed/file/x", "y")"#);
        assert!(inside.contains("could not"), "{inside}");

        let none = new_lua().unwrap();
        install(&none, Rc::new(FsGuard::new(&Permissions::default()))).unwrap();
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
