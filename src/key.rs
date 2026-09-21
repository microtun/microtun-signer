use std::{collections::HashMap, fs, path::Path, sync::RwLock};

use anyhow::{Context, Result, bail};
use ed25519_dalek::{
    Signature, Signer, SigningKey,
    pkcs8::{DecodePrivateKey, EncodePublicKey},
};
use pkcs8::LineEnding;
use zeroize::Zeroizing;

use crate::config::{KeyConfig, KeyState};

pub struct KeyRing {
    keys: HashMap<String, KeyMaterial>,
}

impl KeyRing {
    pub fn load(configs: &[KeyConfig]) -> Result<Self> {
        let mut keys = HashMap::with_capacity(configs.len());
        for config in configs {
            let key = KeyMaterial::load(config)
                .with_context(|| format!("failed to load signing key {}", config.id))?;
            if keys.insert(config.id.clone(), key).is_some() {
                bail!("duplicate signing key id {}", config.id);
            }
        }
        if keys.is_empty() {
            bail!("at least one signing key is required");
        }
        Ok(Self { keys })
    }

    pub fn get(&self, id: &str) -> Option<&KeyMaterial> {
        self.keys.get(id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &KeyMaterial> {
        self.keys.values()
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }
}

pub struct KeyMaterial {
    id: String,
    state: KeyState,
    encrypted_pem: Zeroizing<String>,
    unlocked: RwLock<Option<UnlockedKeyMaterial>>,
}

struct UnlockedKeyMaterial {
    signing_key: SigningKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockOutcome {
    Unlocked,
    AlreadyUnlocked,
}

#[derive(Debug, thiserror::Error)]
pub enum UnlockError {
    #[error("signing key is not active")]
    Inactive,
    #[error("signing key passphrase is invalid or the encrypted key cannot be decrypted")]
    InvalidPassphrase,
    #[error("signing key lock is poisoned")]
    LockPoisoned,
}

impl KeyMaterial {
    pub fn load(config: &KeyConfig) -> Result<Self> {
        check_key_file_permissions(&config.pem_path)?;
        let pem = fs::read_to_string(&config.pem_path).with_context(|| {
            format!("failed to read encrypted key {}", config.pem_path.display())
        })?;
        let begin = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
        let end = "-----END ENCRYPTED PRIVATE KEY-----";
        if pem.matches(begin).count() != 1 || pem.matches(end).count() != 1 {
            bail!(
                "{} must contain exactly one encrypted PKCS#8 PEM block",
                config.pem_path.display()
            );
        }

        Ok(Self {
            id: config.id.clone(),
            state: config.state,
            encrypted_pem: Zeroizing::new(pem),
            unlocked: RwLock::new(None),
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn state(&self) -> KeyState {
        self.state
    }

    pub fn is_unlocked(&self) -> bool {
        self.unlocked
            .read()
            .map(|guard| guard.is_some())
            .unwrap_or(false)
    }

    pub fn public_key_pem(&self) -> Option<String> {
        let guard = self.unlocked.read().ok()?;
        let key = guard.as_ref()?;
        let mut pem = key
            .signing_key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .ok()?;
        if !pem.ends_with('\n') {
            pem.push('\n');
        }
        Some(pem)
    }

    pub fn unlock(&self, passphrase: &str) -> Result<UnlockOutcome, UnlockError> {
        if self.state != KeyState::Active {
            return Err(UnlockError::Inactive);
        }

        {
            let guard = self
                .unlocked
                .read()
                .map_err(|_| UnlockError::LockPoisoned)?;
            if guard.is_some() {
                return Ok(UnlockOutcome::AlreadyUnlocked);
            }
        }

        let signing_key = SigningKey::from_pkcs8_encrypted_pem(
            self.encrypted_pem.as_str(),
            passphrase.as_bytes(),
        )
        .map_err(|_| UnlockError::InvalidPassphrase)?;
        let unlocked = UnlockedKeyMaterial { signing_key };

        let mut guard = self
            .unlocked
            .write()
            .map_err(|_| UnlockError::LockPoisoned)?;
        if guard.is_some() {
            return Ok(UnlockOutcome::AlreadyUnlocked);
        }
        *guard = Some(unlocked);
        Ok(UnlockOutcome::Unlocked)
    }

    pub fn sign_digest(&self, digest: &[u8; 32]) -> Option<[u8; 64]> {
        let guard = self.unlocked.read().ok()?;
        let key = guard.as_ref()?;
        let signature: Signature = key.signing_key.sign(digest);
        Some(signature.to_bytes())
    }
}

pub(crate) fn load_required_secret(
    value_env: &str,
    file_env: &str,
    systemd_credential_name: &str,
    label: &str,
) -> Result<Zeroizing<String>> {
    load_optional_secret(value_env, file_env, systemd_credential_name, label)?
        .with_context(|| format!("{label} is required"))
}

fn load_optional_secret(
    value_env: &str,
    file_env: &str,
    systemd_credential_name: &str,
    label: &str,
) -> Result<Option<Zeroizing<String>>> {
    let direct = std::env::var(value_env).ok().filter(|v| !v.is_empty());
    let explicit_file = std::env::var_os(file_env).filter(|v| !v.is_empty());

    if direct.is_some() && explicit_file.is_some() {
        bail!("set only one of {value_env} or {file_env}");
    }
    if let Some(value) = direct {
        return Ok(Some(Zeroizing::new(value)));
    }

    let (path, check_permissions) = if let Some(path) = explicit_file {
        (Some(std::path::PathBuf::from(path)), true)
    } else {
        (
            std::env::var_os("CREDENTIALS_DIRECTORY")
                .map(std::path::PathBuf::from)
                .map(|dir| dir.join(systemd_credential_name))
                .filter(|path| path.exists()),
            false,
        )
    };

    let Some(path) = path else {
        return Ok(None);
    };

    // Explicit secret files are managed by the caller and must be owner-only.
    // systemd credentials are protected by systemd's credential directory and
    // service sandboxing, and may legitimately be exposed with mode 0440.
    if check_permissions {
        check_secret_file_permissions(&path)?;
    }
    let mut value = fs::read_to_string(&path)
        .with_context(|| format!("failed to read {label} from {}", path.display()))?;
    while value.ends_with('\n') || value.ends_with('\r') {
        value.pop();
    }
    if value.is_empty() {
        bail!("{label} file {} is empty", path.display());
    }
    Ok(Some(Zeroizing::new(value)))
}

#[cfg(unix)]
fn check_key_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(path)
        .with_context(|| format!("failed to stat key file {}", path.display()))?
        .permissions()
        .mode()
        & 0o777;
    // Permit owner-only access (0600) or owner+service-group read access (0640),
    // but never group write/execute or any access for other users.
    if mode & 0o037 != 0 {
        bail!(
            "encrypted key file {} must be owner-only or group-readable only (e.g. 0600/0640; mode {:03o})",
            path.display(),
            mode
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_key_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn check_secret_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(path)
        .with_context(|| format!("failed to stat secret file {}", path.display()))?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        bail!(
            "secret file {} must not be accessible by group/other users (mode {:03o})",
            path.display(),
            mode
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_secret_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Verifier, VerifyingKey};

    use super::*;

    fn test_key(id: &str, state: KeyState) -> KeyMaterial {
        KeyMaterial {
            id: id.into(),
            state,
            encrypted_pem: Zeroizing::new(
                include_str!("../tests/fixtures/test-ed25519-encrypted.pem").to_owned(),
            ),
            unlocked: RwLock::new(None),
        }
    }

    #[test]
    fn encrypted_test_key_starts_locked_then_unlocks_and_signs_exact_digest() {
        let key = test_key("test-key", KeyState::Active);
        assert!(!key.is_unlocked());
        assert!(key.public_key_pem().is_none());
        assert!(key.sign_digest(&[0x5a; 32]).is_none());

        assert_eq!(
            key.unlock("test-passphrase").unwrap(),
            UnlockOutcome::Unlocked
        );
        assert!(key.is_unlocked());
        assert_eq!(
            key.unlock("not-used-after-unlock").unwrap(),
            UnlockOutcome::AlreadyUnlocked
        );

        let digest = [0x5a; 32];
        let signature = Signature::from_bytes(&key.sign_digest(&digest).unwrap());
        let signing_key = SigningKey::from_pkcs8_encrypted_pem(
            include_str!("../tests/fixtures/test-ed25519-encrypted.pem"),
            b"test-passphrase",
        )
        .unwrap();
        let verifying_key = VerifyingKey::from(&signing_key);
        verifying_key.verify(&digest, &signature).unwrap();
        assert!(
            key.public_key_pem()
                .unwrap()
                .starts_with("-----BEGIN PUBLIC KEY-----\n")
        );
    }

    #[test]
    fn wrong_passphrase_does_not_unlock_key() {
        let key = test_key("test-key", KeyState::Active);
        assert!(matches!(
            key.unlock("wrong"),
            Err(UnlockError::InvalidPassphrase)
        ));
        assert!(!key.is_unlocked());
    }

    #[test]
    fn inactive_keys_cannot_be_unlocked() {
        let key = test_key("retired-key", KeyState::Retired);
        assert!(matches!(
            key.unlock("test-passphrase"),
            Err(UnlockError::Inactive)
        ));
    }

    #[test]
    fn key_ring_selects_keys_by_immutable_id() {
        let ring = KeyRing {
            keys: HashMap::from([
                ("key-a".to_owned(), test_key("key-a", KeyState::Active)),
                ("key-b".to_owned(), test_key("key-b", KeyState::Retired)),
            ]),
        };

        assert_eq!(ring.len(), 2);
        assert_eq!(ring.get("key-a").unwrap().state(), KeyState::Active);
        assert_eq!(ring.get("key-b").unwrap().state(), KeyState::Retired);
        assert!(ring.get("missing").is_none());
    }
}
