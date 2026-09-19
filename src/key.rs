use std::{collections::HashMap, fs, path::Path};

use anyhow::{Context, Result, bail};
use ed25519_dalek::{
    Signature, Signer, SigningKey,
    pkcs8::{DecodePrivateKey, EncodePublicKey},
};
use pkcs8::LineEnding;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::config::{KeyConfig, KeyState};

pub const KEY_PASSPHRASE_ENV: &str = "MICROTUN_SIGNER_KEY_PASSPHRASE";
pub const KEY_PASSPHRASE_FILE_ENV: &str = "MICROTUN_SIGNER_KEY_PASSPHRASE_FILE";

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
    signing_key: SigningKey,
    public_key_pem: String,
    fingerprint: String,
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

        let passphrase = load_required_secret(
            KEY_PASSPHRASE_ENV,
            KEY_PASSPHRASE_FILE_ENV,
            &config.passphrase_credential,
            &format!("firmware signing key {} passphrase", config.id),
        )?;
        let signing_key = SigningKey::from_pkcs8_encrypted_pem(&pem, passphrase.as_bytes())
            .context("failed to decrypt/parse Ed25519 PKCS#8 private key")?;

        Self::from_signing_key(config.id.clone(), config.state, signing_key)
    }

    fn from_signing_key(id: String, state: KeyState, signing_key: SigningKey) -> Result<Self> {
        let verifying_key = signing_key.verifying_key();
        let public_der = verifying_key
            .to_public_key_der()
            .context("failed to encode Ed25519 public key as SPKI DER")?;
        let mut public_key_pem = verifying_key
            .to_public_key_pem(LineEnding::LF)
            .context("failed to encode Ed25519 public key as SPKI PEM")?;
        if !public_key_pem.ends_with('\n') {
            public_key_pem.push('\n');
        }
        let fingerprint = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(public_der.as_bytes()))
        );

        Ok(Self {
            id,
            state,
            signing_key,
            public_key_pem,
            fingerprint,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn state(&self) -> KeyState {
        self.state
    }

    pub fn public_key_pem(&self) -> &str {
        &self.public_key_pem
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn sign_digest(&self, digest: &[u8; 32]) -> [u8; 64] {
        let signature: Signature = self.signing_key.sign(digest);
        signature.to_bytes()
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

    let path = if let Some(path) = explicit_file {
        Some(std::path::PathBuf::from(path))
    } else {
        std::env::var_os("CREDENTIALS_DIRECTORY")
            .map(std::path::PathBuf::from)
            .map(|dir| dir.join(systemd_credential_name))
            .filter(|path| path.exists())
    };

    let Some(path) = path else {
        return Ok(None);
    };
    check_secret_file_permissions(&path)?;
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

    #[test]
    fn encrypted_test_key_decrypts_and_signs_exact_digest() {
        let pem = include_str!("../tests/fixtures/test-ed25519-encrypted.pem");
        let signing_key = SigningKey::from_pkcs8_encrypted_pem(pem, b"test-passphrase").unwrap();
        let key = KeyMaterial::from_signing_key("test-key".into(), KeyState::Active, signing_key)
            .unwrap();
        let digest = [0x5a; 32];
        let signature = Signature::from_bytes(&key.sign_digest(&digest));
        let verifying_key = VerifyingKey::from(&key.signing_key);
        verifying_key.verify(&digest, &signature).unwrap();
        assert!(key.fingerprint().starts_with("sha256:"));
        assert!(
            key.public_key_pem()
                .starts_with("-----BEGIN PUBLIC KEY-----\n")
        );
    }

    #[test]
    fn key_ring_selects_keys_by_immutable_id() {
        let pem = include_str!("../tests/fixtures/test-ed25519-encrypted.pem");
        let a = SigningKey::from_pkcs8_encrypted_pem(pem, b"test-passphrase").unwrap();
        let b = SigningKey::from_pkcs8_encrypted_pem(pem, b"test-passphrase").unwrap();
        let ring = KeyRing {
            keys: HashMap::from([
                (
                    "key-a".to_owned(),
                    KeyMaterial::from_signing_key("key-a".into(), KeyState::Active, a).unwrap(),
                ),
                (
                    "key-b".to_owned(),
                    KeyMaterial::from_signing_key("key-b".into(), KeyState::Retired, b).unwrap(),
                ),
            ]),
        };

        assert_eq!(ring.len(), 2);
        assert_eq!(ring.get("key-a").unwrap().state(), KeyState::Active);
        assert_eq!(ring.get("key-b").unwrap().state(), KeyState::Retired);
        assert!(ring.get("missing").is_none());
    }
}
