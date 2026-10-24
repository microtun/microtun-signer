use std::{collections::HashMap, fs, path::Path, sync::RwLock};

use anyhow::{Context, Result, bail};
use k256::ecdsa::{
    Signature as Secp256k1Signature, SigningKey as Secp256k1SigningKey,
    signature::hazmat::PrehashSigner,
};
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use pkcs8::{DecodePrivateKey, EncodePublicKey, LineEnding};
use rand::rngs::OsRng;
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pss::{Signature as RsaPssSignature, SigningKey as RsaPssSigningKey},
    signature::{SignatureEncoding as _, hazmat::RandomizedPrehashSigner as _},
};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::config::{KeyAlgorithm, KeyConfig, KeyState, KeyringConfig};

/// All configured signing keys, in configuration order.
pub struct KeyStore {
    keys: Vec<KeyMaterial>,
    index: HashMap<String, usize>,
    /// Membership is defined by [[Keyring]], in the order of its Keys list.
    keyrings: HashMap<String, Vec<usize>>,
    keyring_by_key: HashMap<String, String>,
}

impl KeyStore {
    pub fn load(configs: &[KeyConfig], keyrings: &[KeyringConfig]) -> Result<Self> {
        let keys = configs
            .iter()
            .map(|config| {
                KeyMaterial::load(config)
                    .with_context(|| format!("failed to load signing key {}", config.id))
            })
            .collect::<Result<Vec<_>>>()?;
        Self::from_keys(keys, keyrings)
    }

    fn from_keys(keys: Vec<KeyMaterial>, keyrings: &[KeyringConfig]) -> Result<Self> {
        if keys.is_empty() {
            bail!("at least one signing key is required");
        }
        let mut index = HashMap::with_capacity(keys.len());
        for (position, key) in keys.iter().enumerate() {
            if index.insert(key.id.clone(), position).is_some() {
                bail!("duplicate signing key id {}", key.id);
            }
        }

        let mut ring_index = HashMap::with_capacity(keyrings.len());
        let mut keyring_by_key = HashMap::new();
        for keyring in keyrings {
            if keyring.keys.is_empty() {
                bail!("keyring {} must contain at least one key", keyring.id);
            }
            let mut members = Vec::with_capacity(keyring.keys.len());
            for key_id in &keyring.keys {
                let &position = index.get(key_id).ok_or_else(|| {
                    anyhow::anyhow!("keyring {} references unknown key {}", keyring.id, key_id)
                })?;
                if let Some(previous) = keyring_by_key.insert(key_id.clone(), keyring.id.clone()) {
                    bail!(
                        "key {} belongs to multiple keyrings ({} and {})",
                        key_id,
                        previous,
                        keyring.id
                    );
                }
                members.push(position);
            }
            if ring_index.insert(keyring.id.clone(), members).is_some() {
                bail!("duplicate keyring id {}", keyring.id);
            }
        }
        Ok(Self {
            keys,
            index,
            keyrings: ring_index,
            keyring_by_key,
        })
    }

    pub fn get(&self, id: &str) -> Option<&KeyMaterial> {
        self.index.get(id).map(|&position| &self.keys[position])
    }

    pub fn iter(&self) -> impl Iterator<Item = &KeyMaterial> {
        self.keys.iter()
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Keys that belong to the named keyring, in its declared Keys order.
    pub fn keyring_members(&self, name: &str) -> impl Iterator<Item = &KeyMaterial> + '_ {
        self.keyrings
            .get(name)
            .into_iter()
            .flatten()
            .map(|&position| &self.keys[position])
    }

    pub fn has_keyring(&self, name: &str) -> bool {
        self.keyrings.contains_key(name)
    }

    pub fn keyring_for_key(&self, key_id: &str) -> Option<&str> {
        self.keyring_by_key.get(key_id).map(String::as_str)
    }

    /// Unlock every active key in a keyring with one passphrase.
    ///
    /// This is all-or-nothing: every locked, active member is decrypted
    /// first, and the decrypted keys are only installed if all of them
    /// succeeded. Members that are already unlocked are left alone and
    /// inactive members are skipped. Each attempt runs the key's KDF, so
    /// callers must run this off the async runtime.
    pub fn unlock_keyring(
        &self,
        name: &str,
        passphrase: &str,
    ) -> Result<Vec<KeyringMemberOutcome>, KeyringUnlockError> {
        let members: Vec<&KeyMaterial> = self.keyring_members(name).collect();
        if members.is_empty() {
            return Err(KeyringUnlockError::UnknownKeyring);
        }
        if members.iter().all(|key| key.state != KeyState::Active) {
            return Err(KeyringUnlockError::NoActiveKeys);
        }

        let mut outcomes = Vec::with_capacity(members.len());
        let mut decrypted = Vec::new();
        let mut opened = Vec::new();
        let mut failed = Vec::new();
        for key in members {
            let result = if key.state != KeyState::Active {
                KeyringMemberResult::SkippedInactive
            } else if key.is_unlocked() {
                KeyringMemberResult::AlreadyUnlocked
            } else {
                match key.decrypt(passphrase) {
                    Ok(material) => {
                        opened.push(key.id.clone());
                        decrypted.push((key, material));
                    }
                    Err(_) => failed.push(key.id.clone()),
                }
                KeyringMemberResult::Unlocked
            };
            outcomes.push(KeyringMemberOutcome {
                key_id: key.id.clone(),
                result,
            });
        }

        if !failed.is_empty() {
            // Dropping `decrypted` zeroizes the keys that did open.
            return Err(if opened.is_empty() {
                KeyringUnlockError::InvalidPassphrase
            } else {
                KeyringUnlockError::PassphraseMismatch { opened, failed }
            });
        }

        // Take every write lock before installing anything, so a poisoned
        // lock cannot leave the keyring partially unlocked.
        let guards = decrypted
            .into_iter()
            .map(|(key, material)| {
                key.unlocked
                    .write()
                    .map(|guard| (key.id.as_str(), guard, material))
                    .map_err(|_| KeyringUnlockError::LockPoisoned)
            })
            .collect::<Result<Vec<_>, _>>()?;
        for (key_id, mut guard, material) in guards {
            if guard.is_some() {
                // Unlocked concurrently since the check above; keep that one.
                if let Some(outcome) = outcomes.iter_mut().find(|o| o.key_id == key_id) {
                    outcome.result = KeyringMemberResult::AlreadyUnlocked;
                }
            } else {
                *guard = Some(material);
            }
        }
        Ok(outcomes)
    }

    #[cfg(test)]
    pub(crate) fn from_keys_for_tests(keys: Vec<KeyMaterial>) -> Self {
        Self::from_keys(keys, &[]).expect("valid test keys")
    }

    #[cfg(test)]
    pub(crate) fn from_keys_with_keyrings_for_tests(
        keys: Vec<KeyMaterial>,
        keyrings: &[KeyringConfig],
    ) -> Self {
        Self::from_keys(keys, keyrings).expect("valid test keys and keyrings")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyringMemberOutcome {
    pub key_id: String,
    pub result: KeyringMemberResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyringMemberResult {
    Unlocked,
    AlreadyUnlocked,
    SkippedInactive,
}

impl KeyringMemberResult {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unlocked => "unlocked",
            Self::AlreadyUnlocked => "already-unlocked",
            Self::SkippedInactive => "skipped-inactive",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeyringUnlockError {
    #[error("no signing keys belong to this keyring")]
    UnknownKeyring,
    #[error("the keyring has no active signing keys")]
    NoActiveKeys,
    #[error("the passphrase did not unlock any key in the keyring")]
    InvalidPassphrase,
    #[error("the passphrase unlocked some keys in the keyring but not others")]
    PassphraseMismatch {
        opened: Vec<String>,
        failed: Vec<String>,
    },
    #[error("signing key lock is poisoned")]
    LockPoisoned,
}

pub struct KeyMaterial {
    id: String,
    algorithm: KeyAlgorithm,
    state: KeyState,
    encrypted_pem: Zeroizing<String>,
    unlocked: RwLock<Option<UnlockedKeyMaterial>>,
}

#[allow(clippy::large_enum_variant)]
enum UnlockedKeyMaterial {
    P256(P256SigningKey),
    Secp256k1(Secp256k1SigningKey),
    RsaPss(RsaPssSigningKey<Sha256>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockOutcome {
    Unlocked,
    AlreadyUnlocked,
}

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("signing key is locked")]
    Locked,
    #[error("signing operation failed")]
    Failed,
}

#[derive(Debug, thiserror::Error)]
pub enum UnlockError {
    #[error("signing key is not active")]
    Inactive,
    #[error(
        "signing key passphrase is invalid, the key cannot be decrypted, or its type does not match the configured algorithm"
    )]
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
            algorithm: config.algorithm,
            state: config.state,
            encrypted_pem: pem,
            unlocked: RwLock::new(None),
        })
    }

    /// Build an active, locked key of the requested algorithm from PEM text.
    #[cfg(test)]
    pub(crate) fn from_pem_with_algorithm_for_tests(
        id: &str,
        algorithm: KeyAlgorithm,
        pem: &str,
    ) -> Self {
        Self {
            id: id.to_owned(),
            algorithm,
            state: KeyState::Active,
            encrypted_pem: Zeroizing::new(pem.to_owned()),
            unlocked: RwLock::new(None),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_state_for_tests(mut self, state: KeyState) -> Self {
        self.state = state;
        self
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
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
        let mut pem = match key {
            UnlockedKeyMaterial::P256(signing_key) => signing_key
                .verifying_key()
                .to_public_key_pem(LineEnding::LF)
                .ok()?,
            UnlockedKeyMaterial::Secp256k1(signing_key) => signing_key
                .verifying_key()
                .to_public_key_pem(LineEnding::LF)
                .ok()?,
            UnlockedKeyMaterial::RsaPss(signing_key) => RsaPublicKey::from(signing_key.as_ref())
                .to_public_key_pem(LineEnding::LF)
                .ok()?,
        };
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

        let unlocked = self.decrypt(passphrase)?;
        self.install(unlocked)
    }

    /// Run the KDF and decrypt the key without changing its lock state.
    fn decrypt(&self, passphrase: &str) -> Result<UnlockedKeyMaterial, UnlockError> {
        let pem = self.encrypted_pem.as_str();
        let passphrase = passphrase.as_bytes();
        match self.algorithm {
            KeyAlgorithm::P256 => P256SigningKey::from_pkcs8_encrypted_pem(pem, passphrase)
                .map(UnlockedKeyMaterial::P256),
            KeyAlgorithm::Secp256k1 => {
                Secp256k1SigningKey::from_pkcs8_encrypted_pem(pem, passphrase)
                    .map(UnlockedKeyMaterial::Secp256k1)
            }
            KeyAlgorithm::RsaPss => RsaPrivateKey::from_pkcs8_encrypted_pem(pem, passphrase)
                .map(RsaPssSigningKey::<Sha256>::new)
                .map(UnlockedKeyMaterial::RsaPss),
        }
        .map_err(|_| UnlockError::InvalidPassphrase)
    }

    fn install(&self, unlocked: UnlockedKeyMaterial) -> Result<UnlockOutcome, UnlockError> {
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

    pub fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>, SignError> {
        let guard = self.unlocked.read().map_err(|_| SignError::Failed)?;
        let key = guard.as_ref().ok_or(SignError::Locked)?;
        match key {
            UnlockedKeyMaterial::P256(signing_key) => {
                let signature: P256Signature = signing_key
                    .sign_prehash(digest)
                    .map_err(|_| SignError::Failed)?;
                Ok(signature.to_bytes().to_vec())
            }
            UnlockedKeyMaterial::Secp256k1(signing_key) => {
                let signature: Secp256k1Signature = signing_key
                    .sign_prehash(digest)
                    .map_err(|_| SignError::Failed)?;
                Ok(signature.to_bytes().to_vec())
            }
            UnlockedKeyMaterial::RsaPss(signing_key) => {
                let signature: RsaPssSignature = signing_key
                    .sign_prehash_with_rng(&mut OsRng, digest)
                    .map_err(|_| SignError::Failed)?;
                Ok(signature.to_vec())
            }
        }
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
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    use rsa::pss::VerifyingKey as RsaPssVerifyingKey;

    use super::*;

    fn test_key(id: &str, state: KeyState) -> KeyMaterial {
        KeyMaterial {
            id: id.into(),
            algorithm: KeyAlgorithm::P256,
            state,
            encrypted_pem: Zeroizing::new(
                include_str!("../tests/fixtures/test-p256-scrypt.pem").to_owned(),
            ),
            unlocked: RwLock::new(None),
        }
    }

    #[test]
    fn encrypted_p256_key_starts_locked_then_unlocks_and_signs_exact_digest_prehash() {
        let key = test_key("test-key", KeyState::Active);
        assert!(!key.is_unlocked());
        assert!(key.public_key_pem().is_none());
        assert!(matches!(
            key.sign_digest(&[0x5a; 32]),
            Err(SignError::Locked)
        ));

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
        let signature_bytes = key.sign_digest(&digest).unwrap();
        assert_eq!(signature_bytes.len(), 64);
        let signature = P256Signature::from_slice(&signature_bytes).unwrap();
        let signing_key = P256SigningKey::from_pkcs8_encrypted_pem(
            include_str!("../tests/fixtures/test-p256-scrypt.pem"),
            b"test-passphrase",
        )
        .unwrap();
        signing_key
            .verifying_key()
            .verify_prehash(&digest, &signature)
            .unwrap();
        assert!(
            key.public_key_pem()
                .unwrap()
                .starts_with("-----BEGIN PUBLIC KEY-----\n")
        );
    }

    #[test]
    fn encrypted_secp256k1_key_unlocks_and_signs_the_digest_as_a_prehash() {
        let key = KeyMaterial::from_pem_with_algorithm_for_tests(
            "secp-key",
            KeyAlgorithm::Secp256k1,
            include_str!("../tests/fixtures/test-secp256k1-scrypt.pem"),
        );
        assert_eq!(key.algorithm(), KeyAlgorithm::Secp256k1);
        assert_eq!(
            key.unlock("test-passphrase").unwrap(),
            UnlockOutcome::Unlocked
        );

        let digest = [0x42; 32];
        let signature_bytes = key.sign_digest(&digest).unwrap();
        let signature = Secp256k1Signature::from_slice(&signature_bytes).unwrap();
        let signing_key = Secp256k1SigningKey::from_pkcs8_encrypted_pem(
            include_str!("../tests/fixtures/test-secp256k1-scrypt.pem"),
            b"test-passphrase",
        )
        .unwrap();
        signing_key
            .verifying_key()
            .verify_prehash(&digest, &signature)
            .unwrap();
        assert!(
            key.public_key_pem()
                .unwrap()
                .starts_with("-----BEGIN PUBLIC KEY-----\n")
        );
    }

    #[test]
    fn encrypted_rsa_pss_key_unlocks_and_signs_the_digest_as_a_sha256_prehash() {
        let key = KeyMaterial::from_pem_with_algorithm_for_tests(
            "rsa-key",
            KeyAlgorithm::RsaPss,
            include_str!("../tests/fixtures/test-rsa-pss-scrypt.pem"),
        );
        assert_eq!(key.algorithm(), KeyAlgorithm::RsaPss);
        assert_eq!(
            key.unlock("test-passphrase").unwrap(),
            UnlockOutcome::Unlocked
        );

        let digest = [0x24; 32];
        let signature_bytes = key.sign_digest(&digest).unwrap();
        assert_eq!(signature_bytes.len(), 256);
        let signature = RsaPssSignature::try_from(signature_bytes.as_slice()).unwrap();
        let private_key = RsaPrivateKey::from_pkcs8_encrypted_pem(
            include_str!("../tests/fixtures/test-rsa-pss-scrypt.pem"),
            b"test-passphrase",
        )
        .unwrap();
        let verifying_key = RsaPssVerifyingKey::<Sha256>::new(RsaPublicKey::from(private_key));
        verifying_key.verify_prehash(&digest, &signature).unwrap();
        assert!(
            key.public_key_pem()
                .unwrap()
                .starts_with("-----BEGIN PUBLIC KEY-----\n")
        );
    }

    #[test]
    fn configured_key_algorithm_must_match_private_key_type() {
        let key = KeyMaterial::from_pem_with_algorithm_for_tests(
            "wrong-algorithm",
            KeyAlgorithm::P256,
            include_str!("../tests/fixtures/test-secp256k1-scrypt.pem"),
        );
        assert!(matches!(
            key.unlock("test-passphrase"),
            Err(UnlockError::InvalidPassphrase)
        ));
    }

    #[test]
    fn p256_and_secp256k1_keys_are_not_interchangeable() {
        let key = KeyMaterial::from_pem_with_algorithm_for_tests(
            "wrong-curve",
            KeyAlgorithm::Secp256k1,
            include_str!("../tests/fixtures/test-p256-scrypt.pem"),
        );
        assert!(matches!(
            key.unlock("test-passphrase"),
            Err(UnlockError::InvalidPassphrase)
        ));
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
            include_str!("../tests/fixtures/test-p256-encrypted.pem"),
            include_str!("../tests/fixtures/test-p256-scrypt-weak.pem"),
            include_str!("../tests/fixtures/test-p256-aes128.pem"),
        ] {
            assert!(enforce_key_encryption_policy(weak).is_err());
        }
    }

    #[test]
    fn strong_key_encryption_is_accepted() {
        for strong in [
            include_str!("../tests/fixtures/test-p256-scrypt.pem"),
            include_str!("../tests/fixtures/test-p256-pbkdf2-600k.pem"),
            include_str!("../tests/fixtures/test-secp256k1-scrypt.pem"),
        ] {
            enforce_key_encryption_policy(strong).unwrap();
        }
    }

    #[test]
    fn documented_scrypt_parameters_unlock_in_rust() {
        P256SigningKey::from_pkcs8_encrypted_pem(
            include_str!("../tests/fixtures/test-p256-scrypt.pem"),
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
            include_str!("../tests/fixtures/test-p256-encrypted.pem"),
        )
        .unwrap();
        fs::write(
            &strong,
            include_str!("../tests/fixtures/test-p256-pbkdf2-600k.pem"),
        )
        .unwrap();
        for path in [&weak, &strong] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let config = |path: &std::path::Path| KeyConfig {
            id: "k".into(),
            algorithm: KeyAlgorithm::P256,
            pem_path: path.to_path_buf(),
            state: KeyState::Active,
            passphrase_credential: None,
        };
        assert!(KeyMaterial::load(&config(&weak)).is_err());
        KeyMaterial::load(&config(&strong)).unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn key_store_selects_keys_by_immutable_id() {
        let store = KeyStore::from_keys_for_tests(vec![
            test_key("key-a", KeyState::Active),
            test_key("key-b", KeyState::Retired),
        ]);

        assert_eq!(store.len(), 2);
        assert_eq!(store.get("key-a").unwrap().state(), KeyState::Active);
        assert_eq!(store.get("key-b").unwrap().state(), KeyState::Retired);
        assert!(store.get("missing").is_none());
        let ids: Vec<_> = store.iter().map(KeyMaterial::id).collect();
        assert_eq!(ids, ["key-a", "key-b"]);
    }

    #[test]
    fn key_store_rejects_duplicate_ids() {
        assert!(
            KeyStore::from_keys(
                vec![
                    test_key("same", KeyState::Active),
                    test_key("same", KeyState::Active),
                ],
                &[],
            )
            .is_err()
        );
    }

    fn fixture(id: &str, algorithm: KeyAlgorithm, pem: &str) -> KeyMaterial {
        KeyMaterial::from_pem_with_algorithm_for_tests(id, algorithm, pem)
    }

    fn keyring(id: &str, keys: &[&str]) -> KeyringConfig {
        KeyringConfig {
            id: id.to_owned(),
            keys: keys.iter().map(|key| (*key).to_owned()).collect(),
        }
    }

    const P256_PEM: &str = include_str!("../tests/fixtures/test-p256-scrypt.pem");
    const SECP256K1_PEM: &str = include_str!("../tests/fixtures/test-secp256k1-scrypt.pem");
    const RSA_PEM: &str = include_str!("../tests/fixtures/test-rsa-pss-scrypt.pem");

    #[test]
    fn keyring_membership_and_order_are_defined_by_keyring_keys() {
        let store = KeyStore::from_keys_with_keyrings_for_tests(
            vec![
                test_key("a", KeyState::Active),
                test_key("b", KeyState::Active),
                test_key("ungrouped", KeyState::Active),
            ],
            &[keyring("fw", &["b", "a"])],
        );
        let members: Vec<_> = store.keyring_members("fw").map(KeyMaterial::id).collect();
        assert_eq!(members, ["b", "a"]);
        assert!(store.has_keyring("fw"));
        assert!(!store.has_keyring("missing"));
        assert_eq!(store.keyring_for_key("a"), Some("fw"));
        assert_eq!(store.keyring_for_key("b"), Some("fw"));
        assert_eq!(store.keyring_for_key("ungrouped"), None);
    }

    #[test]
    fn key_store_rejects_invalid_keyring_membership() {
        for keyrings in [
            vec![keyring("fw", &[])],
            vec![keyring("fw", &["missing"])],
            vec![keyring("fw", &["a", "a"])],
            vec![keyring("fw", &["a"]), keyring("other", &["a"])],
            vec![keyring("fw", &["a"]), keyring("fw", &["b"])],
        ] {
            assert!(
                KeyStore::from_keys(
                    vec![
                        test_key("a", KeyState::Active),
                        test_key("b", KeyState::Active),
                    ],
                    &keyrings,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn keyring_unlocks_every_member_with_one_passphrase() {
        let store = KeyStore::from_keys_with_keyrings_for_tests(
            vec![
                fixture("p256", KeyAlgorithm::P256, P256_PEM),
                fixture("outside", KeyAlgorithm::P256, P256_PEM),
                fixture("k1", KeyAlgorithm::Secp256k1, SECP256K1_PEM),
                fixture("rsa", KeyAlgorithm::RsaPss, RSA_PEM),
            ],
            &[
                keyring("fw", &["p256", "k1", "rsa"]),
                keyring("other", &["outside"]),
            ],
        );
        assert!(store.has_keyring("fw"));

        let outcomes = store.unlock_keyring("fw", "test-passphrase").unwrap();
        let summary: Vec<_> = outcomes
            .iter()
            .map(|o| (o.key_id.as_str(), o.result))
            .collect();
        assert_eq!(
            summary,
            [
                ("p256", KeyringMemberResult::Unlocked),
                ("k1", KeyringMemberResult::Unlocked),
                ("rsa", KeyringMemberResult::Unlocked),
            ]
        );
        for id in ["p256", "k1", "rsa"] {
            let key = store.get(id).unwrap();
            assert!(key.is_unlocked(), "{id}");
            assert!(key.sign_digest(&[7; 32]).is_ok(), "{id}");
        }
        assert!(!store.get("outside").unwrap().is_unlocked());
    }

    #[test]
    fn keyring_unlock_is_all_or_nothing() {
        // The second key is misconfigured, so the shared passphrase cannot
        // open it. Nothing in the keyring may be unlocked as a result.
        let store = KeyStore::from_keys_with_keyrings_for_tests(
            vec![
                fixture("good", KeyAlgorithm::P256, P256_PEM),
                fixture("bad", KeyAlgorithm::P256, SECP256K1_PEM),
            ],
            &[keyring("fw", &["good", "bad"])],
        );
        match store.unlock_keyring("fw", "test-passphrase") {
            Err(KeyringUnlockError::PassphraseMismatch { opened, failed }) => {
                assert_eq!(opened, ["good"]);
                assert_eq!(failed, ["bad"]);
            }
            other => panic!("unexpected result: {other:?}"),
        }
        assert!(!store.get("good").unwrap().is_unlocked());
        assert!(!store.get("bad").unwrap().is_unlocked());
    }

    #[test]
    fn keyring_wrong_passphrase_unlocks_nothing() {
        let store = KeyStore::from_keys_with_keyrings_for_tests(
            vec![
                fixture("a", KeyAlgorithm::P256, P256_PEM),
                fixture("b", KeyAlgorithm::Secp256k1, SECP256K1_PEM),
            ],
            &[keyring("fw", &["a", "b"])],
        );
        assert!(matches!(
            store.unlock_keyring("fw", "wrong"),
            Err(KeyringUnlockError::InvalidPassphrase)
        ));
        assert!(store.iter().all(|key| !key.is_unlocked()));
    }

    #[test]
    fn keyring_skips_inactive_and_already_unlocked_members() {
        let store = KeyStore::from_keys_with_keyrings_for_tests(
            vec![
                fixture("unlocked", KeyAlgorithm::P256, P256_PEM),
                fixture("retired", KeyAlgorithm::P256, P256_PEM)
                    .with_state_for_tests(KeyState::Retired),
                fixture("locked", KeyAlgorithm::Secp256k1, SECP256K1_PEM),
            ],
            &[keyring("fw", &["unlocked", "retired", "locked"])],
        );
        store
            .get("unlocked")
            .unwrap()
            .unlock("test-passphrase")
            .unwrap();

        let outcomes = store.unlock_keyring("fw", "test-passphrase").unwrap();
        let results: Vec<_> = outcomes.iter().map(|o| o.result).collect();
        assert_eq!(
            results,
            [
                KeyringMemberResult::AlreadyUnlocked,
                KeyringMemberResult::SkippedInactive,
                KeyringMemberResult::Unlocked,
            ]
        );
        assert!(!store.get("retired").unwrap().is_unlocked());
    }

    #[test]
    fn keyring_errors_for_unknown_or_inactive_keyrings() {
        let store = KeyStore::from_keys_with_keyrings_for_tests(
            vec![
                fixture("retired", KeyAlgorithm::P256, P256_PEM)
                    .with_state_for_tests(KeyState::Retired),
            ],
            &[keyring("old", &["retired"])],
        );
        assert!(!store.has_keyring("missing"));
        assert!(matches!(
            store.unlock_keyring("missing", "test-passphrase"),
            Err(KeyringUnlockError::UnknownKeyring)
        ));
        assert!(matches!(
            store.unlock_keyring("old", "test-passphrase"),
            Err(KeyringUnlockError::NoActiveKeys)
        ));
    }
}
