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

    #[cfg(test)]
    pub(crate) fn from_keys_for_tests(keys: Vec<KeyMaterial>) -> Self {
        Self {
            keys: keys.into_iter().map(|key| (key.id.clone(), key)).collect(),
        }
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
        // Encrypted keys may be group-readable by the service group (0640),
        // but never group-writable or accessible to other users.
        let pem = read_protected_file(&config.pem_path, 0o037, "encrypted key file")?;
        let begin = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
        let end = "-----END ENCRYPTED PRIVATE KEY-----";
        if pem.matches(begin).count() != 1 || pem.matches(end).count() != 1 {
            bail!(
                "{} must contain exactly one encrypted PKCS#8 PEM block",
                config.pem_path.display()
            );
        }
        enforce_key_encryption_policy(&pem).with_context(|| {
            format!(
                "{} is not encrypted strongly enough",
                config.pem_path.display()
            )
        })?;

        Ok(Self {
            id: config.id.clone(),
            state: config.state,
            encrypted_pem: pem,
            unlocked: RwLock::new(None),
        })
    }

    /// Build an active, locked key from PEM text without file checks.
    #[cfg(test)]
    pub(crate) fn from_pem_for_tests(id: &str, pem: &str) -> Self {
        Self {
            id: id.to_owned(),
            state: KeyState::Active,
            encrypted_pem: Zeroizing::new(pem.to_owned()),
            unlocked: RwLock::new(None),
        }
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

/// Minimum PBKDF2 iterations (OWASP guidance for PBKDF2-HMAC-SHA256).
const MIN_PBKDF2_ITERATIONS: u32 = 600_000;
/// scrypt minimum, using OWASP's equivalent-cost configurations: r >= 8 and
/// N * p >= 2^17 (e.g. N=2^17,p=1 or N=2^14,p=8). The latter is what stock
/// `openssl pkcs8` can produce, as it caps scrypt memory at 32 MiB.
const MIN_SCRYPT_BLOCK_SIZE: u16 = 8;
const MIN_SCRYPT_COST_TIMES_PARALLELISM: u128 = 1 << 17;
/// Upper bounds stop a malformed key file from turning unlock into a
/// memory/CPU exhaustion (scrypt memory is 128 * N * r bytes per lane).
const MAX_SCRYPT_MEMORY_BYTES: u128 = 1 << 30;
const MAX_SCRYPT_WORK: u128 = 1 << 27;
const MAX_PBKDF2_ITERATIONS: u32 = 50_000_000;

const MAX_PROTECTED_FILE_BYTES: u64 = 1024 * 1024;

/// Reject encrypted PKCS#8 keys whose password-based encryption would make
/// an offline brute-force of a copied key file cheap. Only PBES2 with AES-256
/// and either scrypt or PBKDF2-HMAC-SHA-256/512 is accepted.
pub(crate) fn enforce_key_encryption_policy(pem: &str) -> Result<()> {
    use pkcs8::{
        EncryptedPrivateKeyInfo,
        der::Document,
        pkcs5::{
            EncryptionScheme,
            pbes2::{EncryptionScheme as Cipher, Kdf, Pbkdf2Prf},
        },
    };

    let (label, document) =
        Document::from_pem(pem).map_err(|_| anyhow::anyhow!("invalid PEM encoding"))?;
    if label != "ENCRYPTED PRIVATE KEY" {
        bail!("expected an ENCRYPTED PRIVATE KEY PEM block");
    }
    let info = EncryptedPrivateKeyInfo::try_from(document.as_bytes())
        .map_err(|_| anyhow::anyhow!("invalid EncryptedPrivateKeyInfo structure"))?;
    let EncryptionScheme::Pbes2(params) = &info.encryption_algorithm else {
        bail!("PBES1 is not accepted; re-encrypt the key with PBES2");
    };
    if !matches!(params.encryption, Cipher::Aes256Cbc { .. }) {
        bail!("key must be encrypted with AES-256");
    }
    match &params.kdf {
        Kdf::Pbkdf2(pbkdf2) => {
            if !matches!(
                pbkdf2.prf,
                Pbkdf2Prf::HmacWithSha256 | Pbkdf2Prf::HmacWithSha512
            ) {
                bail!("PBKDF2 must use HMAC-SHA-256 or HMAC-SHA-512");
            }
            if pbkdf2.iteration_count < MIN_PBKDF2_ITERATIONS {
                bail!(
                    "PBKDF2 iteration count {} is below the minimum {MIN_PBKDF2_ITERATIONS}",
                    pbkdf2.iteration_count
                );
            }
            if pbkdf2.iteration_count > MAX_PBKDF2_ITERATIONS {
                bail!(
                    "PBKDF2 iteration count {} is unreasonably large",
                    pbkdf2.iteration_count
                );
            }
        }
        Kdf::Scrypt(scrypt) => {
            let n = u128::from(scrypt.cost_parameter);
            let r = u128::from(scrypt.block_size);
            let p = u128::from(scrypt.parallelization);
            if scrypt.block_size < MIN_SCRYPT_BLOCK_SIZE
                || n * p < MIN_SCRYPT_COST_TIMES_PARALLELISM
            {
                bail!(
                    "scrypt parameters N={n} r={r} p={p} are too weak (need r >= {MIN_SCRYPT_BLOCK_SIZE} and N*p >= {MIN_SCRYPT_COST_TIMES_PARALLELISM})"
                );
            }
            if 128 * n * r > MAX_SCRYPT_MEMORY_BYTES || n * r * p > MAX_SCRYPT_WORK {
                bail!("scrypt parameters N={n} r={r} p={p} are unreasonably expensive");
            }
        }
        _ => bail!("unsupported key derivation function"),
    }
    Ok(())
}

/// Read a sensitive file without following a final symlink, validating the
/// same open file descriptor that is read (no stat-then-open race).
///
/// The file must be a regular file owned by root or by the service's
/// effective user, and `mode & forbidden_mode_bits` must be zero.
pub(crate) fn read_protected_file(
    path: &Path,
    forbidden_mode_bits: u32,
    label: &str,
) -> Result<Zeroizing<String>> {
    let file = open_no_follow(path)
        .with_context(|| format!("failed to open {label} {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to stat {label} {}", path.display()))?;
    validate_protected_metadata(&metadata, forbidden_mode_bits).with_context(|| {
        format!(
            "{label} {} has unsafe ownership or permissions",
            path.display()
        )
    })?;
    read_limited(file, &metadata, path, label)
}

fn open_no_follow(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

fn validate_protected_metadata(metadata: &fs::Metadata, forbidden_mode_bits: u32) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if !metadata.file_type().is_file() {
        bail!("not a regular file");
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if metadata.uid() != 0 && metadata.uid() != euid {
        bail!(
            "owned by uid {}; expected root or the service user (uid {euid})",
            metadata.uid()
        );
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & forbidden_mode_bits != 0 {
        bail!("mode {mode:03o} grants access forbidden by mask {forbidden_mode_bits:03o}");
    }
    Ok(())
}

fn read_limited(
    file: fs::File,
    metadata: &fs::Metadata,
    path: &Path,
    label: &str,
) -> Result<Zeroizing<String>> {
    use std::io::Read;

    if metadata.len() > MAX_PROTECTED_FILE_BYTES {
        bail!("{label} {} is unexpectedly large", path.display());
    }
    let mut contents = Zeroizing::new(String::new());
    file.take(MAX_PROTECTED_FILE_BYTES + 1)
        .read_to_string(&mut contents)
        .with_context(|| format!("failed to read {label} {}", path.display()))?;
    if contents.len() as u64 > MAX_PROTECTED_FILE_BYTES {
        bail!("{label} {} is unexpectedly large", path.display());
    }
    Ok(contents)
}

/// Load a secret from the systemd credential `name`, i.e. the file
/// `$CREDENTIALS_DIRECTORY/<name>` that systemd populates from
/// `LoadCredential=`/`LoadCredentialEncrypted=`. Secrets are deliberately not
/// accepted from the environment or from arbitrary file paths.
pub(crate) fn load_systemd_credential(name: &str, label: &str) -> Result<Zeroizing<String>> {
    let directory = std::env::var_os("CREDENTIALS_DIRECTORY")
        .filter(|value| !value.is_empty())
        .with_context(|| {
            format!(
                "{label} is required: provide systemd credential {name} (CREDENTIALS_DIRECTORY is not set)"
            )
        })?;
    load_credential_from(Path::new(&directory), name, label)
}

fn load_credential_from(directory: &Path, name: &str, label: &str) -> Result<Zeroizing<String>> {
    let path = directory.join(name);
    // systemd credentials are protected by the per-service credential
    // directory and may legitimately be exposed with mode 0440 or via ACLs,
    // so only the no-follow/regular-file checks apply here.
    let file = open_no_follow(&path).with_context(|| {
        format!(
            "failed to open {label} (systemd credential {name}) at {}",
            path.display()
        )
    })?;
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to stat {label} {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("{label} {} is not a regular file", path.display());
    }
    let mut value = read_limited(file, &metadata, &path, label)?;
    while value.ends_with('\n') || value.ends_with('\r') {
        value.pop();
    }
    if value.is_empty() {
        bail!("{label} {} is empty", path.display());
    }
    Ok(value)
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
    fn weak_key_encryption_is_rejected() {
        // The original fixture uses openssl's default of 2048 PBKDF2 iterations.
        for weak in [
            include_str!("../tests/fixtures/test-ed25519-encrypted.pem"),
            include_str!("../tests/fixtures/test-ed25519-scrypt-weak.pem"),
            include_str!("../tests/fixtures/test-ed25519-aes128.pem"),
        ] {
            assert!(enforce_key_encryption_policy(weak).is_err());
        }
    }

    #[test]
    fn strong_key_encryption_is_accepted() {
        for strong in [
            include_str!("../tests/fixtures/test-ed25519-scrypt.pem"),
            include_str!("../tests/fixtures/test-ed25519-pbkdf2-600k.pem"),
        ] {
            enforce_key_encryption_policy(strong).unwrap();
        }
    }

    #[test]
    fn documented_scrypt_parameters_unlock_in_rust() {
        SigningKey::from_pkcs8_encrypted_pem(
            include_str!("../tests/fixtures/test-ed25519-scrypt.pem"),
            b"test-passphrase",
        )
        .unwrap();
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "microtun-signer-test-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn protected_files_reject_symlinks_and_loose_modes() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let dir = temp_dir("protected");
        let file = dir.join("secret");
        fs::write(&file, "value\n").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_protected_file(&file, 0o077, "secret")
                .unwrap()
                .as_str(),
            "value\n"
        );

        fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(read_protected_file(&file, 0o077, "secret").is_err());
        assert!(read_protected_file(&file, 0o037, "secret").is_ok());

        let link = dir.join("link");
        symlink(&file, &link).unwrap();
        assert!(read_protected_file(&link, 0o037, "secret").is_err());

        assert!(read_protected_file(&dir, 0o037, "secret").is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn systemd_credentials_are_read_without_following_symlinks() {
        use std::os::unix::fs::symlink;

        let dir = temp_dir("credentials");
        fs::write(dir.join("secret"), "value\r\n").unwrap();
        assert_eq!(
            load_credential_from(&dir, "secret", "secret")
                .unwrap()
                .as_str(),
            "value"
        );

        symlink(dir.join("secret"), dir.join("link")).unwrap();
        assert!(load_credential_from(&dir, "link", "secret").is_err());

        fs::write(dir.join("empty"), "\n").unwrap();
        assert!(load_credential_from(&dir, "empty", "secret").is_err());
        assert!(load_credential_from(&dir, "missing", "secret").is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn key_load_enforces_kdf_policy() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir("keyload");
        let weak = dir.join("weak.pem");
        let strong = dir.join("strong.pem");
        fs::write(
            &weak,
            include_str!("../tests/fixtures/test-ed25519-encrypted.pem"),
        )
        .unwrap();
        fs::write(
            &strong,
            include_str!("../tests/fixtures/test-ed25519-pbkdf2-600k.pem"),
        )
        .unwrap();
        for path in [&weak, &strong] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let config = |path: &std::path::Path| KeyConfig {
            id: "k".into(),
            pem_path: path.to_path_buf(),
            state: KeyState::Active,
            passphrase_credential: None,
        };
        assert!(KeyMaterial::load(&config(&weak)).is_err());
        KeyMaterial::load(&config(&strong)).unwrap();
        fs::remove_dir_all(&dir).unwrap();
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
