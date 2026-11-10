//! Where the CLI keeps a GitHub user's signer session between invocations.
//!
//! The session (access token, its expiry, and the refresh token) is stored in
//! the operating system's credential store when there is one: Keychain on
//! macOS, Credential Manager on Windows, the Secret Service (GNOME Keyring,
//! KWallet, ...) elsewhere. Machines without one, typically headless Linux,
//! fall back to a private file. Setting `MICROTUN_SIGNER_SESSION_CACHE_DIR`
//! selects the file in that directory outright.

use std::{
    env,
    fs::{self, File},
    io::ErrorKind,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use atomic_write_file::AtomicWriteFile;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::oauth::{ACCESS_TOKEN_PREFIX, REFRESH_TOKEN_PREFIX};

const CACHE_VERSION: u8 = 2;
const MAX_SESSION_TOKEN_BYTES: usize = 16 * 1024;
const EXPIRY_SAFETY_MARGIN_SECONDS: u64 = 30;
const CACHE_DIR_ENV: &str = "MICROTUN_SIGNER_SESSION_CACHE_DIR";
const KEYRING_SERVICE: &str = "microtun-signer";

#[derive(Debug, Deserialize)]
struct StoredSession {
    version: u8,
    access_token: String,
    expires_at: u64,
    #[serde(default)]
    refresh_token: Option<String>,
}

#[derive(Serialize)]
struct StoredSessionRef<'a> {
    version: u8,
    access_token: &'a str,
    expires_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<&'a str>,
}

/// What the cache can still offer. At least one of the two is present.
pub struct CachedSession {
    /// Only set while the access token is comfortably inside its lifetime.
    pub access_token: Option<Zeroizing<String>>,
    /// The signer decides whether this is still good; its expiry is not
    /// tracked locally.
    pub refresh_token: Option<Zeroizing<String>>,
}

/// Held while a process renews the cached session, so that concurrent `sign`
/// invocations do not both spend the same single-use refresh token (which the
/// signer would treat as token theft) or both open a browser.
pub struct SessionLock(#[allow(dead_code)] File);

/// Where a session ended up, for telling the user.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stored {
    Keyring,
    File,
    Nowhere,
}

/// One secret slot in a credential store. Errors mean the store cannot be
/// used right now (not installed, locked, access denied), never "not found".
trait SecretStore: Send + Sync {
    fn get(&self) -> Result<Option<Zeroizing<String>>>;
    fn set(&self, secret: &str) -> Result<()>;
    fn delete(&self) -> Result<()>;
}

/// The platform credential store, addressed by signer URL.
struct OsKeyring {
    account: String,
}

impl OsKeyring {
    fn entry(&self) -> Result<keyring::Entry> {
        keyring::Entry::new(KEYRING_SERVICE, &self.account)
            .context("no operating system credential store is available")
    }
}

impl SecretStore for OsKeyring {
    fn get(&self) -> Result<Option<Zeroizing<String>>> {
        match self.entry()?.get_password() {
            Ok(secret) => Ok(Some(Zeroizing::new(secret))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(error).context("failed to read from the credential store"),
        }
    }

    fn set(&self, secret: &str) -> Result<()> {
        self.entry()?
            .set_password(secret)
            .context("failed to write to the credential store")
    }

    fn delete(&self) -> Result<()> {
        match self.entry()?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(error).context("failed to delete from the credential store"),
        }
    }
}

/// The cached session for one signer URL. With neither a credential store
/// nor a cache directory every operation is a no-op and each invocation
/// signs in afresh.
#[derive(Clone)]
pub struct SessionCache {
    keyring: Option<Arc<dyn SecretStore>>,
    /// The fallback file. Its `.lock` sibling is the renewal lock either way.
    path: Option<PathBuf>,
}

impl SessionCache {
    pub fn for_signer(signer_base_url: &Url) -> Self {
        let file_name = session_file_name(signer_base_url);
        // An explicitly chosen directory is a request for the file cache.
        if let Some(root) = absolute_env_path(CACHE_DIR_ENV) {
            return Self {
                keyring: None,
                path: Some(root.join(file_name)),
            };
        }
        Self {
            keyring: Some(Arc::new(OsKeyring {
                account: signer_base_url.to_string(),
            })),
            path: default_cache_root().map(|root| root.join(file_name)),
        }
    }

    /// File cache only, in a directory of the test's choosing.
    #[cfg(test)]
    pub fn in_dir(root: &Path, signer_base_url: &Url) -> Self {
        Self {
            keyring: None,
            path: Some(root.join(session_file_name(signer_base_url))),
        }
    }

    /// Block until this process owns the renewal lock for a signer. Returns
    /// `None` when no cache directory is available. The lock is released when
    /// the returned guard is dropped or the process exits.
    pub fn lock(&self) -> Result<Option<SessionLock>> {
        let Some(path) = self.path.as_deref() else {
            return Ok(None);
        };
        let Some(parent) = path.parent() else {
            return Ok(None);
        };
        ensure_private_dir(parent)?;
        let path = path.with_extension("lock");
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("failed to open signer session lock {}", path.display()))?;
        file.lock()
            .with_context(|| format!("failed to lock signer session cache {}", path.display()))?;
        Ok(Some(SessionLock(file)))
    }

    pub fn load(&self) -> Result<Option<CachedSession>> {
        if let Some(keyring) = &self.keyring {
            // An unusable credential store is not an error: that is exactly
            // the case the file exists for.
            if let Ok(Some(secret)) = keyring.get() {
                let cached = parse_session(secret.as_bytes())?;
                if cached.is_none() {
                    let _ = keyring.delete();
                }
                return Ok(cached);
            }
        }
        self.load_file()
    }

    fn load_file(&self) -> Result<Option<CachedSession>> {
        let Some(path) = self.path.as_deref() else {
            return Ok(None);
        };
        let file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to open signer session cache {}", path.display())
                });
            }
        };
        let metadata = file.metadata().with_context(|| {
            format!("failed to inspect signer session cache {}", path.display())
        })?;
        if !cache_file_is_private(&metadata) {
            let _ = fs::remove_file(path);
            return Ok(None);
        }
        let contents =
            Zeroizing::new(fs::read(path).with_context(|| {
                format!("failed to read signer session cache {}", path.display())
            })?);
        let cached = parse_session(&contents)?;
        if cached.is_none() {
            let _ = fs::remove_file(path);
        }
        Ok(cached)
    }

    pub fn store(
        &self,
        access_token: &str,
        expires_in: u64,
        refresh_token: Option<&str>,
    ) -> Result<Stored> {
        if !valid_token(access_token, ACCESS_TOKEN_PREFIX)
            || expires_in == 0
            || refresh_token.is_some_and(|token| !valid_token(token, REFRESH_TOKEN_PREFIX))
        {
            return Ok(Stored::Nowhere);
        }
        let serialized = Zeroizing::new(
            serde_json::to_string(&StoredSessionRef {
                version: CACHE_VERSION,
                access_token,
                expires_at: unix_time_seconds()?.saturating_add(expires_in),
                refresh_token,
            })
            .context("failed to serialize signer session cache")?,
        );

        if let Some(keyring) = &self.keyring
            && keyring.set(&serialized).is_ok()
        {
            // Never leave an older copy of the tokens behind on disk.
            let _ = self.remove_file();
            return Ok(Stored::Keyring);
        }
        self.store_file(&serialized)
    }

    fn store_file(&self, serialized: &str) -> Result<Stored> {
        let Some(path) = self.path.as_deref() else {
            return Ok(Stored::Nowhere);
        };
        let Some(parent) = path.parent() else {
            return Ok(Stored::Nowhere);
        };
        ensure_private_dir(parent)?;

        let mut file = AtomicWriteFile::open(path)
            .with_context(|| format!("failed to open signer session cache {}", path.display()))?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to secure signer session cache {}", path.display()))?;
        std::io::Write::write_all(&mut file, serialized.as_bytes())
            .context("failed to write signer session cache")?;
        file.sync_all()
            .context("failed to flush signer session cache")?;
        file.commit()
            .with_context(|| format!("failed to commit signer session cache {}", path.display()))?;
        Ok(Stored::File)
    }

    /// Forget the session everywhere it might be.
    pub fn remove(&self) -> Result<()> {
        if let Some(keyring) = &self.keyring {
            // Unavailable store: nothing of ours can be in it.
            let _ = keyring.delete();
        }
        self.remove_file()
    }

    fn remove_file(&self) -> Result<()> {
        let Some(path) = self.path.as_deref() else {
            return Ok(());
        };
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).with_context(|| {
                format!("failed to remove signer session cache {}", path.display())
            }),
        }
    }
}

/// `None` for anything that is of no further use: unparseable, from another
/// cache version, or holding neither a live access token nor a refresh token.
fn parse_session(serialized: &[u8]) -> Result<Option<CachedSession>> {
    let Ok(stored) = serde_json::from_slice::<StoredSession>(serialized) else {
        return Ok(None);
    };
    let access_token = Zeroizing::new(stored.access_token);
    let refresh_token = stored.refresh_token.map(Zeroizing::new);

    let now = unix_time_seconds()?;
    let cached = CachedSession {
        access_token: Some(access_token).filter(|token| {
            valid_token(token, ACCESS_TOKEN_PREFIX)
                && stored.expires_at > now.saturating_add(EXPIRY_SAFETY_MARGIN_SECONDS)
        }),
        refresh_token: refresh_token.filter(|token| valid_token(token, REFRESH_TOKEN_PREFIX)),
    };
    if stored.version != CACHE_VERSION
        || (cached.access_token.is_none() && cached.refresh_token.is_none())
    {
        return Ok(None);
    }
    Ok(Some(cached))
}

fn session_file_name(signer_base_url: &Url) -> String {
    let digest = Sha256::digest(signer_base_url.as_str().as_bytes());
    format!("{}.json", hex::encode(digest))
}

fn default_cache_root() -> Option<PathBuf> {
    dirs::runtime_dir()
        .or_else(dirs::cache_dir)
        .map(|path| path.join("microtun-signer/sessions"))
}

fn absolute_env_path(name: &str) -> Option<PathBuf> {
    let value = env::var_os(name)?;
    if value.is_empty() {
        return None;
    }
    let path = PathBuf::from(value);
    path.is_absolute().then_some(path)
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)
        .with_context(|| format!("failed to create signer session cache {}", path.display()))?;
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect signer session cache {}", path.display()))?;
    if !metadata.is_dir() {
        anyhow::bail!(
            "signer session cache path is not a private directory: {}",
            path.display()
        );
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        anyhow::bail!(
            "signer session cache is not owned by the current user: {}",
            path.display()
        );
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to secure signer session cache {}", path.display()))?;
    }
    Ok(())
}

fn cache_file_is_private(metadata: &fs::Metadata) -> bool {
    metadata.is_file()
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.permissions().mode() & 0o077 == 0
}

fn valid_token(token: &str, prefix: &str) -> bool {
    token.len() > prefix.len()
        && token.starts_with(prefix)
        && token.len() <= MAX_SESSION_TOKEN_BYTES
        && !token.chars().any(char::is_whitespace)
}

fn unix_time_seconds() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_key_is_scoped_to_signer_url() {
        let first = Url::parse("https://signer.example/").unwrap();
        let second = Url::parse("https://other.example/").unwrap();
        assert_ne!(session_file_name(&first), session_file_name(&second));
    }

    #[test]
    fn only_signer_local_tokens_are_cacheable() {
        assert!(valid_token("mts_abc123", ACCESS_TOKEN_PREFIX));
        assert!(valid_token("mtr_abc123", REFRESH_TOKEN_PREFIX));
        assert!(!valid_token("mtr_abc123", ACCESS_TOKEN_PREFIX));
        assert!(!valid_token("gho_abc123", ACCESS_TOKEN_PREFIX));
        assert!(!valid_token("mts_has space", ACCESS_TOKEN_PREFIX));
        assert!(!valid_token("mts_", ACCESS_TOKEN_PREFIX));
        assert!(!valid_token("", ACCESS_TOKEN_PREFIX));
    }

    #[test]
    fn stored_sessions_keep_the_refresh_token_optional() {
        let stored: StoredSession = serde_json::from_str(
            r#"{"version":2,"access_token":"mts_a","expires_at":1,"refresh_token":"mtr_b"}"#,
        )
        .unwrap();
        assert_eq!(stored.refresh_token.as_deref(), Some("mtr_b"));
        let stored: StoredSession =
            serde_json::from_str(r#"{"version":2,"access_token":"mts_a","expires_at":1}"#).unwrap();
        assert!(stored.refresh_token.is_none());

        let text = serde_json::to_string(&StoredSessionRef {
            version: CACHE_VERSION,
            access_token: "mts_a",
            expires_at: 1,
            refresh_token: None,
        })
        .unwrap();
        assert!(!text.contains("refresh_token"), "{text}");
    }

    /// An in-memory credential store that can be switched off.
    #[derive(Default)]
    struct FakeKeyring {
        secret: std::sync::Mutex<Option<String>>,
        unavailable: std::sync::atomic::AtomicBool,
    }

    impl FakeKeyring {
        fn check(&self) -> Result<()> {
            if self.unavailable.load(std::sync::atomic::Ordering::SeqCst) {
                anyhow::bail!("credential store is unavailable");
            }
            Ok(())
        }

        fn set_unavailable(&self, unavailable: bool) {
            self.unavailable
                .store(unavailable, std::sync::atomic::Ordering::SeqCst);
        }

        fn secret(&self) -> Option<String> {
            self.secret.lock().unwrap().clone()
        }
    }

    impl SecretStore for FakeKeyring {
        fn get(&self) -> Result<Option<Zeroizing<String>>> {
            self.check()?;
            Ok(self.secret().map(Zeroizing::new))
        }

        fn set(&self, secret: &str) -> Result<()> {
            self.check()?;
            *self.secret.lock().unwrap() = Some(secret.to_owned());
            Ok(())
        }

        fn delete(&self) -> Result<()> {
            self.check()?;
            *self.secret.lock().unwrap() = None;
            Ok(())
        }
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let path = env::temp_dir().join(format!(
                "microtun-signer-cache-test-{}-{name}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn cache_with_keyring(dir: &TempDir) -> (SessionCache, Arc<FakeKeyring>) {
        let keyring = Arc::new(FakeKeyring::default());
        let cache = SessionCache {
            keyring: Some(keyring.clone()),
            path: Some(dir.0.join("session.json")),
        };
        (cache, keyring)
    }

    fn access_token(cache: &SessionCache) -> Option<String> {
        cache
            .load()
            .unwrap()
            .and_then(|cached| cached.access_token)
            .map(|token| token.to_string())
    }

    #[test]
    fn keyring_is_preferred_and_nothing_is_written_to_disk() {
        let dir = TempDir::new("preferred");
        let (cache, keyring) = cache_with_keyring(&dir);

        assert_eq!(
            cache.store("mts_a", 900, Some("mtr_a")).unwrap(),
            Stored::Keyring
        );
        assert!(keyring.secret().unwrap().contains("mtr_a"));
        assert!(!dir.0.join("session.json").exists());

        let cached = cache.load().unwrap().unwrap();
        assert_eq!(
            cached.access_token.as_deref().map(String::as_str),
            Some("mts_a")
        );
        assert_eq!(
            cached.refresh_token.as_deref().map(String::as_str),
            Some("mtr_a")
        );

        cache.remove().unwrap();
        assert!(keyring.secret().is_none());
        assert!(cache.load().unwrap().is_none());
    }

    #[test]
    fn file_is_the_fallback_when_the_keyring_is_unavailable() {
        let dir = TempDir::new("fallback");
        let (cache, keyring) = cache_with_keyring(&dir);
        keyring.set_unavailable(true);

        assert_eq!(
            cache.store("mts_a", 900, Some("mtr_a")).unwrap(),
            Stored::File
        );
        let path = dir.0.join("session.json");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(access_token(&cache).as_deref(), Some("mts_a"));

        // Once the keyring works again the session moves there and the file
        // copy is deleted rather than left behind.
        keyring.set_unavailable(false);
        assert_eq!(access_token(&cache).as_deref(), Some("mts_a"));
        assert_eq!(
            cache.store("mts_b", 900, Some("mtr_b")).unwrap(),
            Stored::Keyring
        );
        assert!(!path.exists());
        assert_eq!(access_token(&cache).as_deref(), Some("mts_b"));
    }

    #[test]
    fn useless_keyring_entries_are_deleted() {
        let dir = TempDir::new("useless");
        let (cache, keyring) = cache_with_keyring(&dir);
        for useless in [
            "not json",
            r#"{"version":1,"access_token":"mts_a","expires_at":99999999999}"#,
            r#"{"version":2,"access_token":"mts_a","expires_at":1}"#,
        ] {
            keyring.set(useless).unwrap();
            assert!(cache.load().unwrap().is_none(), "{useless}");
            assert!(keyring.secret().is_none(), "{useless}");
        }

        // An expired access token is still worth keeping for its refresh token.
        keyring
            .set(r#"{"version":2,"access_token":"mts_a","expires_at":1,"refresh_token":"mtr_a"}"#)
            .unwrap();
        let cached = cache.load().unwrap().unwrap();
        assert!(cached.access_token.is_none());
        assert_eq!(
            cached.refresh_token.as_deref().map(String::as_str),
            Some("mtr_a")
        );
    }

    /// Talks to the real platform credential store, so it only runs on
    /// request: `cargo test -- --ignored os_keyring` in a desktop session
    /// (or under `dbus-run-session` with an unlocked Secret Service).
    /// It runs inside the async runtime because that is where the CLI calls it.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs an operating system credential store"]
    async fn os_keyring_round_trip() {
        let dir = TempDir::new("os-keyring");
        let cache = SessionCache {
            keyring: Some(Arc::new(OsKeyring {
                account: format!("https://test-{}.invalid/", std::process::id()),
            })),
            path: Some(dir.0.join("session.json")),
        };
        assert_eq!(
            cache.store("mts_a", 900, Some("mtr_a")).unwrap(),
            Stored::Keyring
        );
        assert!(!dir.0.join("session.json").exists());
        let cached = cache.load().unwrap().unwrap();
        assert_eq!(
            cached.refresh_token.as_deref().map(String::as_str),
            Some("mtr_a")
        );
        cache.remove().unwrap();
        assert!(cache.load().unwrap().is_none());
    }

    #[test]
    fn renewal_lock_excludes_other_holders() {
        let dir = TempDir::new("lock");
        let cache = SessionCache::in_dir(&dir.0, &Url::parse("https://signer.example/").unwrap());
        let held = cache.lock().unwrap().unwrap();
        let contender = fs::OpenOptions::new()
            .write(true)
            .open(
                dir.0
                    .join(session_file_name(
                        &Url::parse("https://signer.example/").unwrap(),
                    ))
                    .with_extension("lock"),
            )
            .unwrap();
        assert!(contender.try_lock().is_err());
        drop(held);
        contender.try_lock().unwrap();
    }
}
