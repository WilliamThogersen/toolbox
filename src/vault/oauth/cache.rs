use std::fs::{self, DirBuilder, File, OpenOptions, TryLockError};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use serde::{Deserialize, Serialize};

use super::random_bytes;
use crate::cli::paths;
use crate::vault::SecretValue;

const FORMAT: u32 = 1;
const FRESH_MARGIN_SECS: u64 = 60;
const MAX_FILE_BYTES: u64 = 64 * 1024;
const LOCK_WAIT: Duration = Duration::from_secs(40);
const LOCK_POLL: Duration = Duration::from_millis(50);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sealed {
    format: u32,
    nonce: String,
    data: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plain {
    access_token: String,
    refresh_token: String,
    expires_at: u64,
}

#[derive(Debug, Clone)]
pub struct Cached {
    pub access: SecretValue,
    pub refresh: SecretValue,
    pub expires_at: u64,
}

impl Cached {
    pub fn fresh(&self, now: u64) -> bool {
        self.expires_at > now.saturating_add(FRESH_MARGIN_SECS)
    }
}

pub struct TokenCache {
    pub dir: PathBuf,
}

impl TokenCache {
    pub fn in_home() -> Result<Self> {
        Ok(Self { dir: paths::toolbox_home()?.join("oauth") })
    }

    fn file(&self, name: &str, extension: &str) -> PathBuf {
        self.dir.join(format!("{}.{extension}", name.replace('/', ".")))
    }

    pub fn read(&self, name: &str, cache_key: &SecretValue) -> Option<Cached> {
        let file = open_plain(&self.file(name, "json"), OpenOptions::new().read(true)).ok()?;
        let mut raw = Vec::new();
        file.take(MAX_FILE_BYTES + 1).read_to_end(&mut raw).ok()?;
        if u64::try_from(raw.len()).ok()? > MAX_FILE_BYTES {
            return None;
        }
        let sealed: Sealed = serde_json::from_slice(&raw).ok()?;
        if sealed.format != FORMAT {
            return None;
        }
        let nonce: [u8; NONCE_LEN] = STANDARD.decode(sealed.nonce).ok()?.try_into().ok()?;
        let mut data = STANDARD.decode(sealed.data).ok()?;
        let aad = aad(name);
        let plain = key_for(cache_key)
            .ok()?
            .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(aad.as_bytes()), &mut data)
            .ok()?;
        let plain: Plain = serde_json::from_slice(plain).ok()?;
        Some(Cached {
            access: SecretValue::new(plain.access_token).ok()?,
            refresh: SecretValue::new(plain.refresh_token).ok()?,
            expires_at: plain.expires_at,
        })
    }

    pub fn write(&self, name: &str, cache_key: &SecretValue, cached: &Cached) -> Result<()> {
        self.make_dir()?;
        let plain = Plain {
            access_token: cached.access.expose().to_string(),
            refresh_token: cached.refresh.expose().to_string(),
            expires_at: cached.expires_at,
        };
        let mut data = serde_json::to_vec(&plain)?;
        let nonce = random_bytes::<NONCE_LEN>()?;
        let aad = aad(name);
        key_for(cache_key)?
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(aad.as_bytes()), &mut data)
            .map_err(|_| anyhow!("could not encrypt the token"))?;
        let sealed = Sealed { format: FORMAT, nonce: STANDARD.encode(nonce), data: STANDARD.encode(data) };
        let (path, temp) = (self.file(name, "json"), self.file(name, "json.tmp"));
        let mut file = open_plain(&temp, OpenOptions::new().create(true).write(true).truncate(true).mode(0o600))?;
        file.write_all(&serde_json::to_vec(&sealed)?)?;
        fs::rename(&temp, &path).with_context(|| format!("could not write {}", path.display()))
    }

    pub fn lock(&self, name: &str) -> Result<File> {
        self.make_dir()?;
        let path = self.file(name, "lock");
        let file = open_plain(&path, OpenOptions::new().create(true).truncate(false).write(true).mode(0o600))?;
        let deadline = Instant::now() + LOCK_WAIT;
        while Instant::now() < deadline {
            match file.try_lock() {
                Ok(()) => return Ok(file),
                Err(TryLockError::WouldBlock) => thread::sleep(LOCK_POLL),
                Err(TryLockError::Error(err)) => {
                    return Err(err).with_context(|| format!("could not lock {}", path.display()));
                }
            }
        }
        bail!("another run kept {} locked for {} s, so the token for {name} was not renewed", path.display(), LOCK_WAIT.as_secs())
    }

    pub fn forget(&self, name: &str) -> Result<()> {
        for path in [self.file(name, "json"), self.file(name, "lock")] {
            match fs::remove_file(&path) {
                Err(err) if err.kind() != std::io::ErrorKind::NotFound => {
                    return Err(err).with_context(|| format!("could not remove {}", path.display()));
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn make_dir(&self) -> Result<()> {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)
            .with_context(|| format!("could not create {}", self.dir.display()))
    }
}

fn open_plain(path: &Path, options: &mut OpenOptions) -> Result<File> {
    let file = options
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("could not open {}", path.display()))?;
    ensure!(file.metadata()?.is_file(), "{} is not a plain file", path.display());
    Ok(file)
}

fn key_for(cache_key: &SecretValue) -> Result<LessSafeKey> {
    let bytes = URL_SAFE_NO_PAD.decode(cache_key.expose()).context("the vault's cache key is broken")?;
    let key = UnboundKey::new(&CHACHA20_POLY1305, &bytes).map_err(|_| anyhow!("the vault's cache key is broken"))?;
    Ok(LessSafeKey::new(key))
}

fn aad(name: &str) -> String {
    format!("toolbox oauth token cache {FORMAT} {name}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::oauth::new_cache_key;

    fn value(text: &str) -> SecretValue {
        SecretValue::new(text.to_string()).unwrap()
    }

    fn cached() -> Cached {
        Cached { access: value("fake_access_token_1"), refresh: value("fake_refresh_token_1"), expires_at: 2_000 }
    }

    #[test]
    fn tokens_round_trip_encrypted() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = TokenCache { dir: tmp.path().join("oauth") };
        let key = new_cache_key().unwrap();
        assert!(cache.read("google/work", &key).is_none());
        cache.write("google/work", &key, &cached()).unwrap();

        let on_disk = fs::read_to_string(tmp.path().join("oauth/google.work.json")).unwrap();
        assert!(!on_disk.contains("fake_access") && !on_disk.contains("fake_refresh"), "{on_disk}");
        let back = cache.read("google/work", &key).unwrap();
        assert_eq!((back.access.expose(), back.refresh.expose(), back.expires_at), ("fake_access_token_1", "fake_refresh_token_1", 2_000));
        let mode = fs::metadata(tmp.path().join("oauth/google.work.json")).unwrap().permissions();
        assert_eq!(std::os::unix::fs::PermissionsExt::mode(&mode) & 0o777, 0o600);
        let dir_mode = fs::metadata(tmp.path().join("oauth")).unwrap().permissions();
        assert_eq!(std::os::unix::fs::PermissionsExt::mode(&dir_mode) & 0o777, 0o700);
    }

    #[test]
    fn another_key_or_a_moved_file_reads_as_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = TokenCache { dir: tmp.path().to_path_buf() };
        let key = new_cache_key().unwrap();
        cache.write("google", &key, &cached()).unwrap();
        assert!(cache.read("google", &new_cache_key().unwrap()).is_none(), "a new sign-in makes old tokens unreadable");
        fs::copy(tmp.path().join("google.json"), tmp.path().join("github.json")).unwrap();
        assert!(cache.read("github", &key).is_none(), "a file moved to another key's name is refused");

        let mut sealed: serde_json::Value = serde_json::from_slice(&fs::read(tmp.path().join("google.json")).unwrap()).unwrap();
        let mut data = STANDARD.decode(sealed["data"].as_str().unwrap()).unwrap();
        data[0] ^= 1;
        sealed["data"] = STANDARD.encode(data).into();
        fs::write(tmp.path().join("google.json"), sealed.to_string()).unwrap();
        assert!(cache.read("google", &key).is_none(), "a changed byte is refused");
        fs::write(tmp.path().join("google.json"), "x".repeat(usize::try_from(MAX_FILE_BYTES).unwrap() + 1)).unwrap();
        assert!(cache.read("google", &key).is_none());
    }

    #[test]
    fn links_pipes_and_endless_files_read_as_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = TokenCache { dir: tmp.path().to_path_buf() };
        let key = new_cache_key().unwrap();
        std::os::unix::fs::symlink("/dev/zero", tmp.path().join("zero.json")).unwrap();
        assert!(cache.read("zero", &key).is_none());
        assert!(std::process::Command::new("mkfifo").arg(tmp.path().join("pipe.json")).status().unwrap().success());
        assert!(cache.read("pipe", &key).is_none(), "a pipe must not block");
        std::process::Command::new("mkfifo").arg(tmp.path().join("pipe.lock")).status().unwrap();
        assert!(cache.lock("pipe").is_err());
        assert!(cache.write("pipe", &key, &cached()).is_ok(), "the rename replaces the pipe");
        std::os::unix::fs::symlink(tmp.path().join("elsewhere"), tmp.path().join("linked.json.tmp")).unwrap();
        assert!(cache.write("linked", &key, &cached()).is_err());
        assert!(!tmp.path().join("elsewhere").exists());
    }

    #[test]
    fn freshness_leaves_a_margin() {
        let token = cached();
        assert!(token.fresh(2_000 - FRESH_MARGIN_SECS - 1));
        assert!(!token.fresh(2_000 - FRESH_MARGIN_SECS));
        assert!(!token.fresh(u64::MAX));
    }

    #[test]
    fn forget_removes_the_files_and_tolerates_none() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = TokenCache { dir: tmp.path().to_path_buf() };
        let key = new_cache_key().unwrap();
        cache.write("google", &key, &cached()).unwrap();
        drop(cache.lock("google").unwrap());
        cache.forget("google").unwrap();
        assert!(fs::read_dir(tmp.path()).unwrap().next().is_none());
        cache.forget("google").unwrap();
    }
}
