use std::{
    env,
    fs::{self, File},
    io::ErrorKind,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use atomic_write_file::AtomicWriteFile;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const CACHE_VERSION: u8 = 1;
const SESSION_TOKEN_PREFIX: &str = "mts_";
const MAX_SESSION_TOKEN_BYTES: usize = 16 * 1024;
const EXPIRY_SAFETY_MARGIN_SECONDS: u64 = 30;

#[derive(Debug, Deserialize)]
struct CachedSession {
    version: u8,
    access_token: String,
    expires_at: u64,
}

#[derive(Serialize)]
struct CachedSessionRef<'a> {
    version: u8,
    access_token: &'a str,
    expires_at: u64,
}

pub fn load(signer_base_url: &Url) -> Result<Option<Zeroizing<String>>> {
    let Some(path) = session_path(signer_base_url) else {
        return Ok(None);
    };

    let file = match File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| {
                format!("failed to open signer session cache {}", path.display())
            });
        }
    };

    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect signer session cache {}", path.display()))?;
    if !cache_file_is_private(&metadata) {
        let _ = fs::remove_file(&path);
        return Ok(None);
    }

    let mut cached: CachedSession = match serde_json::from_reader(file) {
        Ok(cached) => cached,
        Err(_) => {
            let _ = fs::remove_file(&path);
            return Ok(None);
        }
    };

    let now = unix_time_seconds()?;
    if cached.version != CACHE_VERSION
        || !valid_session_token(&cached.access_token)
        || cached.expires_at <= now.saturating_add(EXPIRY_SAFETY_MARGIN_SECONDS)
    {
        cached.access_token.zeroize();
        let _ = fs::remove_file(&path);
        return Ok(None);
    }

    Ok(Some(Zeroizing::new(cached.access_token)))
}

pub fn store(signer_base_url: &Url, access_token: &str, expires_in: u64) -> Result<bool> {
    if !valid_session_token(access_token) || expires_in == 0 {
        return Ok(false);
    }

    let Some(path) = session_path(signer_base_url) else {
        return Ok(false);
    };
    let Some(parent) = path.parent() else {
        return Ok(false);
    };
    ensure_private_dir(parent)?;

    let expires_at = unix_time_seconds()?.saturating_add(expires_in);
    let cached = CachedSessionRef {
        version: CACHE_VERSION,
        access_token,
        expires_at,
    };

    let mut file = AtomicWriteFile::open(&path)
        .with_context(|| format!("failed to open signer session cache {}", path.display()))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to secure signer session cache {}", path.display()))?;
    serde_json::to_writer(&mut file, &cached)
        .context("failed to serialize signer session cache")?;
    file.sync_all()
        .context("failed to flush signer session cache")?;
    file.commit()
        .with_context(|| format!("failed to commit signer session cache {}", path.display()))?;
    Ok(true)
}

pub fn remove(signer_base_url: &Url) -> Result<()> {
    let Some(path) = session_path(signer_base_url) else {
        return Ok(());
    };
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("failed to remove signer session cache {}", path.display())),
    }
}

fn session_path(signer_base_url: &Url) -> Option<PathBuf> {
    let root = cache_root()?;
    let digest = Sha256::digest(signer_base_url.as_str().as_bytes());
    Some(root.join(format!("{}.json", hex::encode(digest))))
}

fn cache_root() -> Option<PathBuf> {
    if let Some(path) = absolute_env_path("MICROTUN_SIGNER_SESSION_CACHE_DIR") {
        return Some(path);
    }

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

fn valid_session_token(token: &str) -> bool {
    token.starts_with(SESSION_TOKEN_PREFIX)
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
        let first_digest = Sha256::digest(first.as_str().as_bytes());
        let second_digest = Sha256::digest(second.as_str().as_bytes());
        assert_ne!(first_digest, second_digest);
    }

    #[test]
    fn only_signer_local_tokens_are_cacheable() {
        assert!(valid_session_token("mts_abc123"));
        assert!(!valid_session_token("gho_abc123"));
        assert!(!valid_session_token("mts_has space"));
        assert!(!valid_session_token(""));
    }
}
