//! Local development signing: `--url local:` instead of a signer service.
//!
//! The CLI then signs in-process with an unencrypted key from a directory on
//! this machine. Nothing listens, nobody authenticates and nothing is
//! unlocked, so builds and tests that sign through `microtun-signer` work
//! offline with exactly the command lines they use against a real signer.
//!
//! This is a development convenience and deliberately not a deployment mode:
//!
//! - The service (`serve`) never reads this store, and the store never reads
//!   the service's encrypted keys.
//! - Local keys are kept in a separate store from the signer service's keys;
//!   the same key ID may be used in either store.
//! - Keys are created explicitly (`local init`/`local import`). Signing with
//!   an unknown ID fails instead of minting a key, and an existing key is
//!   never replaced.
//! - Every signature prints a warning on stderr. stdout carries only the
//!   signature or public key, as with a remote signer.

use std::{
    env, fs,
    io::{ErrorKind, Write as _},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use clap::{Args, Subcommand, ValueEnum};
use k256::ecdsa::SigningKey as Secp256k1SigningKey;
use p256::ecdsa::SigningKey as P256SigningKey;
use pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rand::rngs::OsRng;
use rsa::{
    RsaPrivateKey, pkcs1::DecodeRsaPrivateKey, pss::SigningKey as RsaPssSigningKey,
    traits::PublicKeyParts,
};
use sha2::Sha256;
use ulid::Ulid;
use zeroize::Zeroizing;

use crate::{
    client::{PublicKeyArgs, SignArgs},
    config::KeyAlgorithm,
    key::{UnlockedKeyMaterial, read_protected_file},
    valid_key_id,
};

/// `--url` values starting with this select local signing.
const URL_SCHEME: &str = "local:";
/// Overrides the default store directory for a bare `local:` URL.
const DIR_ENV: &str = "MICROTUN_SIGNER_LOCAL_DIR";
const DEFAULT_RSA_BITS: usize = 3072;
const SUPPORTED_RSA_BITS: [usize; 3] = [2048, 3072, 4096];

const PRIVATE_SUFFIX: &str = ".pem";
const PUBLIC_SUFFIX: &str = ".pub.pem";

#[derive(Debug, Args)]
pub struct LocalArgs {
    /// Directory holding the local keys. Defaults to the directory named by a
    /// `local:/absolute/dir` --url, then MICROTUN_SIGNER_LOCAL_DIR, then
    /// microtun-signer/local in the user data directory.
    #[arg(long, global = true)]
    dir: Option<PathBuf>,

    #[command(subcommand)]
    command: LocalCommand,
}

#[derive(Debug, Subcommand)]
enum LocalCommand {
    /// Create a local development key unless it already exists.
    Init(InitArgs),

    /// Copy an existing unencrypted private key into the local store.
    Import(ImportArgs),

    /// List the local keys as `<key-id><TAB><algorithm>`.
    List,

    /// Print the store directory, or with --key-id that key's public-key file.
    Path(PathArgs),
}

#[derive(Debug, Args)]
struct InitArgs {
    /// Key ID to create (1–128 ASCII letters, digits, `.`, `_` or `-`).
    #[arg(short = 'k', long = "key-id", env = "MICROTUN_SIGNER_KEY_ID")]
    key_id: String,

    #[arg(short = 'a', long, value_enum)]
    algorithm: AlgorithmArg,

    /// RSA modulus size for rsa-pss keys: 2048, 3072 or 4096 [default: 3072].
    #[arg(long)]
    rsa_bits: Option<usize>,
}

#[derive(Debug, Args)]
struct ImportArgs {
    /// Key ID to create (1–128 ASCII letters, digits, `.`, `_` or `-`).
    #[arg(short = 'k', long = "key-id", env = "MICROTUN_SIGNER_KEY_ID")]
    key_id: String,

    #[arg(short = 'a', long, value_enum)]
    algorithm: AlgorithmArg,

    /// Unencrypted PEM private key: PKCS#8, or the traditional OpenSSL
    /// `EC PRIVATE KEY`/`RSA PRIVATE KEY` formats. The file is left in place.
    #[arg(long)]
    pem: PathBuf,
}

#[derive(Debug, Args)]
struct PathArgs {
    #[arg(short = 'k', long = "key-id", env = "MICROTUN_SIGNER_KEY_ID")]
    key_id: Option<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum AlgorithmArg {
    #[value(alias = "secp256r1")]
    P256,
    Secp256k1,
    #[value(name = "rsa-pss")]
    RsaPss,
}

impl From<AlgorithmArg> for KeyAlgorithm {
    fn from(value: AlgorithmArg) -> Self {
        match value {
            AlgorithmArg::P256 => Self::P256,
            AlgorithmArg::Secp256k1 => Self::Secp256k1,
            AlgorithmArg::RsaPss => Self::RsaPss,
        }
    }
}

/// Whether `--url` selects local signing rather than a signer service.
pub fn is_local_url(url: &str) -> bool {
    url.starts_with(URL_SCHEME)
}

/// The store directory named by a local URL, if it names one. `local:` and
/// `local://` name none; `local:/dir` and `local:///dir` name `/dir`. The
/// path is taken literally (no percent-decoding).
fn url_dir(url: &str) -> Result<Option<PathBuf>> {
    let rest = url
        .strip_prefix(URL_SCHEME)
        .ok_or_else(|| anyhow!("not a local: URL"))?;
    let rest = rest.strip_prefix("//").unwrap_or(rest);
    if rest.is_empty() {
        return Ok(None);
    }
    let dir = PathBuf::from(rest);
    if !dir.is_absolute() {
        bail!("a local: URL must be `local:` or name an absolute directory (local:/path/to/keys)");
    }
    Ok(Some(dir))
}

/// `sign --url local:...`
pub fn sign(url: &str, args: &SignArgs) -> Result<()> {
    let decoded = BASE64
        .decode(args.digest.as_bytes())
        .context("--digest must be valid base64")?;
    let digest: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow!("--digest must decode to exactly 32 bytes"))?;

    let store = LocalStore::resolve(None, Some(url))?;
    let key = store.load(&args.key_id)?;
    let signature = key
        .sign_digest(&digest)
        .map_err(|_| anyhow!("local signing operation failed"))?;
    eprintln!(
        "warning: signed with LOCAL development key {} from {}; never ship artifacts signed with local keys",
        args.key_id,
        store.dir.display()
    );
    println!("{}", BASE64.encode(signature));
    Ok(())
}

/// `public-key --url local:...`
pub fn public_key(url: &str, args: &PublicKeyArgs) -> Result<()> {
    let store = LocalStore::resolve(None, Some(url))?;
    let key = store.load(&args.key_id)?;
    print!("{}", public_pem(&key)?);
    Ok(())
}

/// `local <subcommand>`
pub fn run(args: LocalArgs, url: Option<&str>) -> Result<()> {
    let store = LocalStore::resolve(args.dir.as_deref(), url)?;
    match args.command {
        LocalCommand::Init(init) => {
            let algorithm = KeyAlgorithm::from(init.algorithm);
            if init.rsa_bits.is_some() && algorithm != KeyAlgorithm::RsaPss {
                bail!("--rsa-bits only applies to --algorithm rsa-pss");
            }
            let outcome = store.init(&init.key_id, algorithm, init.rsa_bits)?;
            report(&store, &init.key_id, algorithm, outcome);
        }
        LocalCommand::Import(import) => {
            let algorithm = KeyAlgorithm::from(import.algorithm);
            let pem = Zeroizing::new(
                fs::read_to_string(&import.pem)
                    .with_context(|| format!("failed to read {}", import.pem.display()))?,
            );
            let outcome = store.import(&import.key_id, algorithm, &pem)?;
            report(&store, &import.key_id, algorithm, outcome);
        }
        LocalCommand::List => {
            for (key_id, algorithm) in store.list()? {
                println!("{key_id}\t{}", algorithm.as_str());
            }
        }
        LocalCommand::Path(path) => match path.key_id {
            None => println!("{}", store.dir.display()),
            Some(key_id) => {
                let key = store.load(&key_id)?;
                store.write_public(&key_id, &key)?;
                println!("{}", store.public_path(&key_id).display());
            }
        },
    }
    Ok(())
}

fn report(store: &LocalStore, key_id: &str, algorithm: KeyAlgorithm, outcome: Outcome) {
    let algorithm = algorithm.as_str();
    let dir = store.dir.display();
    match outcome {
        Outcome::Created => println!("created local {algorithm} key {key_id} in {dir}"),
        Outcome::AlreadyPresent => {
            println!("local {algorithm} key {key_id} already exists in {dir}")
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Created,
    AlreadyPresent,
}

/// A directory of unencrypted development keys: `<key-id>.pem` (PKCS#8, mode
/// 0600) with a derived `<key-id>.pub.pem` beside it. The private key file is
/// authoritative; its algorithm is whatever key it contains.
struct LocalStore {
    dir: PathBuf,
}

impl LocalStore {
    /// Precedence: --dir, the directory in a `local:/dir` URL,
    /// MICROTUN_SIGNER_LOCAL_DIR, the user data directory.
    fn resolve(flag: Option<&Path>, url: Option<&str>) -> Result<Self> {
        if let Some(dir) = flag {
            let dir = std::path::absolute(dir)
                .with_context(|| format!("invalid --dir {}", dir.display()))?;
            return Ok(Self { dir });
        }
        if let Some(url) = url.filter(|url| is_local_url(url))
            && let Some(dir) = url_dir(url)?
        {
            return Ok(Self { dir });
        }
        if let Some(dir) = env::var_os(DIR_ENV).filter(|value| !value.is_empty()) {
            let dir = PathBuf::from(dir);
            if !dir.is_absolute() {
                bail!("{DIR_ENV} must be an absolute path");
            }
            return Ok(Self { dir });
        }
        let data = dirs::data_dir().context(
            "cannot determine the user data directory; set MICROTUN_SIGNER_LOCAL_DIR or use local:/absolute/dir",
        )?;
        Ok(Self {
            dir: data.join("microtun-signer").join("local"),
        })
    }

    fn private_path(&self, key_id: &str) -> PathBuf {
        self.dir.join(format!("{key_id}{PRIVATE_SUFFIX}"))
    }

    fn public_path(&self, key_id: &str) -> PathBuf {
        self.dir.join(format!("{key_id}{PUBLIC_SUFFIX}"))
    }

    /// Load a key for signing. Never creates anything.
    fn load(&self, key_id: &str) -> Result<UnlockedKeyMaterial> {
        validate_local_key_id(key_id)?;
        self.load_existing(key_id)?.ok_or_else(|| {
            anyhow!(
                "unknown local signing key {key_id} in {}; create it with `microtun-signer local init --key-id {key_id} --algorithm <p256|secp256k1|rsa-pss>`",
                self.dir.display()
            )
        })
    }

    fn load_existing(&self, key_id: &str) -> Result<Option<UnlockedKeyMaterial>> {
        let path = self.private_path(key_id);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| format!("failed to stat {}", path.display()));
            }
            Ok(_) => {}
        }
        self.check_dir()?;
        // Owner-only, like any other private key file.
        let pem = read_protected_file(&path, 0o077, "local signing key")?;
        parse_stored(&pem)
            .with_context(|| format!("{} is not a usable local signing key", path.display()))
            .map(Some)
    }

    fn init(
        &self,
        key_id: &str,
        algorithm: KeyAlgorithm,
        rsa_bits: Option<usize>,
    ) -> Result<Outcome> {
        validate_local_key_id(key_id)?;
        if let Some(bits) = rsa_bits
            && !SUPPORTED_RSA_BITS.contains(&bits)
        {
            bail!("--rsa-bits must be 2048, 3072 or 4096");
        }
        self.prepare_dir()?;
        if self.load_existing(key_id)?.is_none() {
            let key = generate(algorithm, rsa_bits.unwrap_or(DEFAULT_RSA_BITS))?;
            if self.publish_private(key_id, &key)? {
                self.write_public(key_id, &key)?;
                return Ok(Outcome::Created);
            }
            // Lost a race with another `init`; fall through to its key.
        }
        let existing = self.load(key_id)?;
        if existing.algorithm() != algorithm {
            bail!(
                "local key {key_id} already exists with algorithm {}, not {}",
                existing.algorithm().as_str(),
                algorithm.as_str()
            );
        }
        if let (Some(wanted), Some(actual)) = (rsa_bits, rsa_bits_of(&existing))
            && wanted != actual
        {
            bail!("local key {key_id} already exists as RSA-{actual}, not RSA-{wanted}");
        }
        self.write_public(key_id, &existing)?;
        Ok(Outcome::AlreadyPresent)
    }

    fn import(&self, key_id: &str, algorithm: KeyAlgorithm, pem: &str) -> Result<Outcome> {
        validate_local_key_id(key_id)?;
        let key = parse_import(algorithm, pem)?;
        self.prepare_dir()?;
        if self.load_existing(key_id)?.is_none() && self.publish_private(key_id, &key)? {
            self.write_public(key_id, &key)?;
            return Ok(Outcome::Created);
        }
        let existing = self.load(key_id)?;
        if public_pem(&existing)? != public_pem(&key)? {
            bail!(
                "local key {key_id} already exists and is a different key; local keys are never replaced (remove {} yourself if that is really intended)",
                self.private_path(key_id).display()
            );
        }
        self.write_public(key_id, &existing)?;
        Ok(Outcome::AlreadyPresent)
    }

    fn list(&self) -> Result<Vec<(String, KeyAlgorithm)>> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to read {}", self.dir.display()));
            }
        };
        let mut keys = Vec::new();
        for entry in entries {
            let name = entry
                .with_context(|| format!("failed to read {}", self.dir.display()))?
                .file_name();
            let Some(name) = name.to_str() else { continue };
            if name.ends_with(PUBLIC_SUFFIX) {
                continue;
            }
            let Some(key_id) = name.strip_suffix(PRIVATE_SUFFIX) else {
                continue;
            };
            if !valid_key_id(key_id) {
                continue;
            }
            if let Some(key) = self.load_existing(key_id)? {
                keys.push((key_id.to_owned(), key.algorithm()));
            }
        }
        keys.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(keys)
    }

    /// Create the store directory (owner-only) if needed and check it.
    fn prepare_dir(&self) -> Result<()> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)
            .with_context(|| format!("failed to create {}", self.dir.display()))?;
        self.check_dir()
    }

    /// Whoever can write to the directory can swap the keys in it.
    fn check_dir(&self) -> Result<()> {
        let metadata = fs::metadata(&self.dir)
            .with_context(|| format!("failed to stat {}", self.dir.display()))?;
        if !metadata.is_dir() {
            bail!("local key store {} is not a directory", self.dir.display());
        }
        // SAFETY: geteuid has no preconditions and cannot fail.
        let euid = unsafe { libc::geteuid() };
        if metadata.uid() != 0 && metadata.uid() != euid {
            bail!(
                "local key store {} is owned by uid {}; expected you (uid {euid}) or root",
                self.dir.display(),
                metadata.uid()
            );
        }
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o022 != 0 {
            bail!(
                "local key store {} must not be writable by group/other users (mode {mode:03o})",
                self.dir.display()
            );
        }
        Ok(())
    }

    /// Publish a new private key without ever replacing an existing one: the
    /// finished file is hard-linked into place, which fails if the name is
    /// taken. Returns false when another key got there first.
    fn publish_private(&self, key_id: &str, key: &UnlockedKeyMaterial) -> Result<bool> {
        let pem = private_pem(key)?;
        let target = self.private_path(key_id);
        let staged = self.write_staged(key_id, pem.as_bytes(), 0o600)?;
        let linked = fs::hard_link(&staged, &target);
        let _ = fs::remove_file(&staged);
        match linked {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => Ok(false),
            Err(error) => {
                Err(error).with_context(|| format!("failed to create {}", target.display()))
            }
        }
    }

    /// (Re)write the public-key file derived from `key`. It is a convenience
    /// copy for build systems; signing never reads it.
    fn write_public(&self, key_id: &str, key: &UnlockedKeyMaterial) -> Result<()> {
        let pem = public_pem(key)?;
        let target = self.public_path(key_id);
        if fs::read_to_string(&target).is_ok_and(|current| current == pem) {
            return Ok(());
        }
        let staged = self.write_staged(key_id, pem.as_bytes(), 0o644)?;
        fs::rename(&staged, &target)
            .inspect_err(|_| {
                let _ = fs::remove_file(&staged);
            })
            .with_context(|| format!("failed to write {}", target.display()))
    }

    fn write_staged(&self, key_id: &str, contents: &[u8], mode: u32) -> Result<PathBuf> {
        let staged = self.dir.join(format!(".{key_id}.{}.tmp", Ulid::new()));
        let write = || -> std::io::Result<()> {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&staged)?;
            // The mode above is subject to the umask.
            file.set_permissions(fs::Permissions::from_mode(mode))?;
            file.write_all(contents)?;
            file.sync_all()
        };
        write()
            .inspect_err(|_| {
                let _ = fs::remove_file(&staged);
            })
            .with_context(|| format!("failed to write {}", staged.display()))?;
        Ok(staged)
    }
}

fn validate_local_key_id(key_id: &str) -> Result<()> {
    if !valid_key_id(key_id) {
        bail!("--key-id must match [A-Za-z0-9._-]{{1,128}}");
    }
    Ok(())
}

fn generate(algorithm: KeyAlgorithm, rsa_bits: usize) -> Result<UnlockedKeyMaterial> {
    Ok(match algorithm {
        KeyAlgorithm::P256 => UnlockedKeyMaterial::P256(P256SigningKey::random(&mut OsRng)),
        KeyAlgorithm::Secp256k1 => {
            UnlockedKeyMaterial::Secp256k1(Secp256k1SigningKey::random(&mut OsRng))
        }
        KeyAlgorithm::RsaPss => {
            let key = RsaPrivateKey::new(&mut OsRng, rsa_bits)
                .context("failed to generate an RSA key")?;
            UnlockedKeyMaterial::RsaPss(RsaPssSigningKey::<Sha256>::new(key))
        }
    })
}

/// Parse a key file written by this store. The file says what it is.
fn parse_stored(pem: &str) -> Result<UnlockedKeyMaterial> {
    [
        KeyAlgorithm::P256,
        KeyAlgorithm::Secp256k1,
        KeyAlgorithm::RsaPss,
    ]
    .into_iter()
    .find_map(|algorithm| parse_pkcs8(algorithm, pem))
    .ok_or_else(|| anyhow!("expected an unencrypted PKCS#8 P-256, secp256k1 or RSA private key"))
}

fn parse_pkcs8(algorithm: KeyAlgorithm, pem: &str) -> Option<UnlockedKeyMaterial> {
    match algorithm {
        KeyAlgorithm::P256 => P256SigningKey::from_pkcs8_pem(pem)
            .ok()
            .map(UnlockedKeyMaterial::P256),
        KeyAlgorithm::Secp256k1 => Secp256k1SigningKey::from_pkcs8_pem(pem)
            .ok()
            .map(UnlockedKeyMaterial::Secp256k1),
        KeyAlgorithm::RsaPss => RsaPrivateKey::from_pkcs8_pem(pem)
            .ok()
            .map(|key| UnlockedKeyMaterial::RsaPss(RsaPssSigningKey::<Sha256>::new(key))),
    }
}

/// Parse a key handed to `local import`: PKCS#8, or the traditional SEC1/
/// PKCS#1 PEM that `openssl ecparam -genkey` and older tools write.
fn parse_import(algorithm: KeyAlgorithm, pem: &str) -> Result<UnlockedKeyMaterial> {
    if pem.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----") || pem.contains("Proc-Type:") {
        bail!(
            "the key is passphrase-protected; local keys are stored unencrypted, so decrypt it first (openssl pkey -in encrypted.pem -out plain.pem)"
        );
    }
    let traditional = || match algorithm {
        KeyAlgorithm::P256 => p256::SecretKey::from_sec1_pem(pem)
            .ok()
            .map(|key| UnlockedKeyMaterial::P256(P256SigningKey::from(key))),
        KeyAlgorithm::Secp256k1 => k256::SecretKey::from_sec1_pem(pem)
            .ok()
            .map(|key| UnlockedKeyMaterial::Secp256k1(Secp256k1SigningKey::from(key))),
        KeyAlgorithm::RsaPss => RsaPrivateKey::from_pkcs1_pem(pem)
            .ok()
            .map(|key| UnlockedKeyMaterial::RsaPss(RsaPssSigningKey::<Sha256>::new(key))),
    };
    let key = parse_pkcs8(algorithm, pem)
        .or_else(traditional)
        .ok_or_else(|| {
            anyhow!(
                "the file is not an unencrypted PEM private key for --algorithm {}",
                algorithm.as_str()
            )
        })?;
    if let Some(bits) = rsa_bits_of(&key)
        && bits < 2048
    {
        bail!("RSA-{bits} keys are too small; use at least 2048 bits");
    }
    Ok(key)
}

fn rsa_bits_of(key: &UnlockedKeyMaterial) -> Option<usize> {
    match key {
        UnlockedKeyMaterial::RsaPss(signing_key) => {
            let private: &RsaPrivateKey = signing_key.as_ref();
            Some(private.n().bits())
        }
        _ => None,
    }
}

fn private_pem(key: &UnlockedKeyMaterial) -> Result<Zeroizing<String>> {
    match key {
        UnlockedKeyMaterial::P256(signing_key) => signing_key.to_pkcs8_pem(LineEnding::LF),
        UnlockedKeyMaterial::Secp256k1(signing_key) => signing_key.to_pkcs8_pem(LineEnding::LF),
        UnlockedKeyMaterial::RsaPss(signing_key) => {
            let private: &RsaPrivateKey = signing_key.as_ref();
            private.to_pkcs8_pem(LineEnding::LF)
        }
    }
    .map_err(|_| anyhow!("failed to encode the private key as PKCS#8"))
}

fn public_pem(key: &UnlockedKeyMaterial) -> Result<String> {
    key.public_key_pem()
        .context("failed to encode the public key")
}

#[cfg(test)]
mod tests {
    use k256::ecdsa::{Signature as Secp256k1Signature, VerifyingKey as Secp256k1VerifyingKey};
    use p256::ecdsa::{
        Signature as P256Signature, VerifyingKey as P256VerifyingKey,
        signature::hazmat::PrehashVerifier,
    };
    use pkcs8::DecodePublicKey;
    use rsa::{
        RsaPublicKey,
        pss::{Signature as RsaPssSignature, VerifyingKey as RsaPssVerifyingKey},
    };

    use super::*;

    struct TempStore {
        root: PathBuf,
        store: LocalStore,
    }

    impl TempStore {
        fn new(name: &str) -> Self {
            let root = env::temp_dir().join(format!(
                "microtun-signer-local-{name}-{}-{}",
                std::process::id(),
                Ulid::new()
            ));
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            let store = LocalStore {
                dir: root.join("keys"),
            };
            Self { root, store }
        }
    }

    impl std::ops::Deref for TempStore {
        type Target = LocalStore;
        fn deref(&self) -> &LocalStore {
            &self.store
        }
    }

    impl Drop for TempStore {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    const DIGEST: [u8; 32] = [0x5a; 32];

    #[test]
    fn local_urls_name_an_optional_absolute_directory() {
        assert!(is_local_url("local:"));
        assert!(is_local_url("local:/keys"));
        assert!(!is_local_url("https://signer.example.com/"));
        assert!(!is_local_url("http://localhost:8080/"));
        assert!(!is_local_url("LOCAL:"));

        assert_eq!(url_dir("local:").unwrap(), None);
        assert_eq!(url_dir("local://").unwrap(), None);
        assert_eq!(
            url_dir("local:/var/keys").unwrap(),
            Some(PathBuf::from("/var/keys"))
        );
        assert_eq!(
            url_dir("local:///var/keys").unwrap(),
            Some(PathBuf::from("/var/keys"))
        );
        assert!(url_dir("local:keys").is_err());
        assert!(url_dir("local://keys").is_err());
    }

    #[test]
    fn store_directory_precedence_is_flag_then_url() {
        let flag = LocalStore::resolve(Some(Path::new("/from/flag")), Some("local:/from/url"));
        assert_eq!(flag.unwrap().dir, PathBuf::from("/from/flag"));
        let url = LocalStore::resolve(None, Some("local:/from/url"));
        assert_eq!(url.unwrap().dir, PathBuf::from("/from/url"));
        // A remote signer URL in the environment does not affect `local` subcommands.
        let remote = LocalStore::resolve(
            Some(Path::new("/from/flag")),
            Some("https://signer.example.com"),
        );
        assert_eq!(remote.unwrap().dir, PathBuf::from("/from/flag"));
    }

    #[test]
    fn local_key_ids_use_the_same_rules_as_signer_key_ids() {
        for id in [
            "local",
            "ferriboot-local-p256",
            "microtun-firmware-prod",
            "ferriboot-dev-p256-v1",
            "localhost",
            "nonlocal-key",
            "Local-key",
            "a.b_c-9",
        ] {
            assert!(validate_local_key_id(id).is_ok(), "{id}");
        }
        for id in ["", "local/key", "space in id", "é"] {
            assert!(validate_local_key_id(id).is_err(), "{id}");
        }
        assert!(validate_local_key_id(&"a".repeat(129)).is_err());
    }

    #[test]
    fn init_creates_an_owner_only_p256_key_that_signs_the_digest_as_a_prehash() {
        let store = TempStore::new("p256");
        let id = "test-local-p256";
        assert_eq!(
            store.init(id, KeyAlgorithm::P256, None).unwrap(),
            Outcome::Created
        );
        assert_eq!(mode(&store.dir), 0o700);
        assert_eq!(mode(&store.private_path(id)), 0o600);
        assert_eq!(mode(&store.public_path(id)), 0o644);
        assert!(
            fs::read_to_string(store.private_path(id))
                .unwrap()
                .starts_with("-----BEGIN PRIVATE KEY-----\n")
        );

        let key = store.load(id).unwrap();
        assert_eq!(key.algorithm(), KeyAlgorithm::P256);
        let public = public_pem(&key).unwrap();
        assert_eq!(fs::read_to_string(store.public_path(id)).unwrap(), public);

        let signature = key.sign_digest(&DIGEST).unwrap();
        assert_eq!(signature.len(), 64);
        P256VerifyingKey::from_public_key_pem(&public)
            .unwrap()
            .verify_prehash(&DIGEST, &P256Signature::from_slice(&signature).unwrap())
            .unwrap();
    }

    #[test]
    fn init_creates_a_secp256k1_key() {
        let store = TempStore::new("k256");
        let id = "test-local-k1";
        store.init(id, KeyAlgorithm::Secp256k1, None).unwrap();
        let key = store.load(id).unwrap();
        assert_eq!(key.algorithm(), KeyAlgorithm::Secp256k1);
        let signature = key.sign_digest(&DIGEST).unwrap();
        assert_eq!(signature.len(), 64);
        Secp256k1VerifyingKey::from_public_key_pem(&public_pem(&key).unwrap())
            .unwrap()
            .verify_prehash(
                &DIGEST,
                &Secp256k1Signature::from_slice(&signature).unwrap(),
            )
            .unwrap();
    }

    #[test]
    fn init_creates_an_rsa_pss_key() {
        let store = TempStore::new("rsa");
        let id = "test-local-rsa";
        store.init(id, KeyAlgorithm::RsaPss, Some(2048)).unwrap();
        let key = store.load(id).unwrap();
        assert_eq!(key.algorithm(), KeyAlgorithm::RsaPss);
        assert_eq!(rsa_bits_of(&key), Some(2048));
        let signature = key.sign_digest(&DIGEST).unwrap();
        assert_eq!(signature.len(), 256);
        let public = RsaPublicKey::from_public_key_pem(&public_pem(&key).unwrap()).unwrap();
        RsaPssVerifyingKey::<Sha256>::new(public)
            .verify_prehash(
                &DIGEST,
                &RsaPssSignature::try_from(signature.as_slice()).unwrap(),
            )
            .unwrap();

        // An existing key satisfies a matching request and refuses others.
        assert_eq!(
            store.init(id, KeyAlgorithm::RsaPss, Some(2048)).unwrap(),
            Outcome::AlreadyPresent
        );
        assert_eq!(
            store.init(id, KeyAlgorithm::RsaPss, None).unwrap(),
            Outcome::AlreadyPresent
        );
        assert!(store.init(id, KeyAlgorithm::RsaPss, Some(3072)).is_err());
        assert!(store.init(id, KeyAlgorithm::RsaPss, Some(1024)).is_err());
    }

    #[test]
    fn init_never_replaces_an_existing_key() {
        let store = TempStore::new("idempotent");
        let id = "test-local-key";
        store.init(id, KeyAlgorithm::P256, None).unwrap();
        let before = fs::read_to_string(store.private_path(id)).unwrap();

        assert_eq!(
            store.init(id, KeyAlgorithm::P256, None).unwrap(),
            Outcome::AlreadyPresent
        );
        let error = store
            .init(id, KeyAlgorithm::Secp256k1, None)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("already exists with algorithm p256"),
            "{error}"
        );
        assert_eq!(fs::read_to_string(store.private_path(id)).unwrap(), before);

        // A missing public-key file is derived again.
        fs::remove_file(store.public_path(id)).unwrap();
        store.init(id, KeyAlgorithm::P256, None).unwrap();
        assert_eq!(
            fs::read_to_string(store.public_path(id)).unwrap(),
            public_pem(&store.load(id).unwrap()).unwrap()
        );
    }

    #[test]
    fn concurrent_init_agrees_on_one_key() {
        let store = TempStore::new("race");
        let id = "test-local-race";
        store.prepare_dir().unwrap();
        let created = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| store.init(id, KeyAlgorithm::P256, None).unwrap()))
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .filter(|outcome| *outcome == Outcome::Created)
                .count()
        });
        assert_eq!(created, 1);
        assert_eq!(
            fs::read_to_string(store.public_path(id)).unwrap(),
            public_pem(&store.load(id).unwrap()).unwrap()
        );
        // No staging files are left behind.
        assert_eq!(fs::read_dir(&store.dir).unwrap().count(), 2);
    }

    #[test]
    fn unknown_keys_fail_without_creating_anything() {
        let store = TempStore::new("unknown");
        for id in ["test-local-missing", "microtun-firmware-prod"] {
            let error = store.load(id).err().unwrap().to_string();
            assert!(error.contains("local init"), "{error}");
        }
        assert!(!store.dir.exists());
    }

    #[test]
    fn keys_without_local_in_the_id_can_be_created_imported_loaded_and_listed() {
        let store = TempStore::new("arbitrary-ids");
        assert_eq!(
            store
                .init("firmware-prod", KeyAlgorithm::P256, None)
                .unwrap(),
            Outcome::Created
        );
        assert_eq!(
            store.load("firmware-prod").unwrap().algorithm(),
            KeyAlgorithm::P256
        );

        let key = P256SigningKey::random(&mut OsRng)
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap();
        assert_eq!(
            store.import("device_1", KeyAlgorithm::P256, &key).unwrap(),
            Outcome::Created
        );
        assert_eq!(
            store.load("device_1").unwrap().algorithm(),
            KeyAlgorithm::P256
        );
        assert_eq!(
            store.list().unwrap(),
            vec![
                ("device_1".to_owned(), KeyAlgorithm::P256),
                ("firmware-prod".to_owned(), KeyAlgorithm::P256),
            ]
        );
    }

    #[test]
    fn import_accepts_pkcs8_and_traditional_pem_and_is_idempotent() {
        let store = TempStore::new("import");

        let p256 = P256SigningKey::random(&mut OsRng);
        let pkcs8 = p256.to_pkcs8_pem(LineEnding::LF).unwrap();
        assert_eq!(
            store
                .import("test-local-p256", KeyAlgorithm::P256, &pkcs8)
                .unwrap(),
            Outcome::Created
        );
        assert_eq!(mode(&store.private_path("test-local-p256")), 0o600);
        let expected = UnlockedKeyMaterial::P256(p256).public_key_pem().unwrap();
        assert_eq!(
            public_pem(&store.load("test-local-p256").unwrap()).unwrap(),
            expected
        );
        assert_eq!(
            store
                .import("test-local-p256", KeyAlgorithm::P256, &pkcs8)
                .unwrap(),
            Outcome::AlreadyPresent
        );

        // A different key under an existing ID is refused.
        let other = P256SigningKey::random(&mut OsRng)
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap();
        let error = store
            .import("test-local-p256", KeyAlgorithm::P256, &other)
            .unwrap_err()
            .to_string();
        assert!(error.contains("never replaced"), "{error}");
        assert_eq!(
            public_pem(&store.load("test-local-p256").unwrap()).unwrap(),
            expected
        );

        // `openssl ecparam -genkey` style SEC1 PEM.
        let k1 = k256::SecretKey::random(&mut OsRng);
        let sec1 = k1.to_sec1_pem(LineEnding::LF).unwrap();
        assert!(sec1.starts_with("-----BEGIN EC PRIVATE KEY-----"));
        store
            .import("test-local-k1", KeyAlgorithm::Secp256k1, &sec1)
            .unwrap();
        assert_eq!(
            public_pem(&store.load("test-local-k1").unwrap()).unwrap(),
            UnlockedKeyMaterial::Secp256k1(Secp256k1SigningKey::from(k1))
                .public_key_pem()
                .unwrap()
        );
        // Stored keys are always PKCS#8, whatever was imported.
        assert!(
            fs::read_to_string(store.private_path("test-local-k1"))
                .unwrap()
                .starts_with("-----BEGIN PRIVATE KEY-----\n")
        );

        assert_eq!(
            store.list().unwrap(),
            vec![
                ("test-local-k1".to_owned(), KeyAlgorithm::Secp256k1),
                ("test-local-p256".to_owned(), KeyAlgorithm::P256),
            ]
        );
    }

    #[test]
    fn import_rejects_encrypted_and_mismatched_keys() {
        let store = TempStore::new("import-reject");
        let encrypted = include_str!("../tests/fixtures/test-p256-scrypt.pem");
        let error = store
            .import("test-local-p256", KeyAlgorithm::P256, encrypted)
            .unwrap_err()
            .to_string();
        assert!(error.contains("passphrase-protected"), "{error}");

        let p256 = P256SigningKey::random(&mut OsRng)
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap();
        assert!(
            store
                .import("test-local-k1", KeyAlgorithm::Secp256k1, &p256)
                .is_err()
        );
        assert!(
            store
                .import("test-local-rsa", KeyAlgorithm::RsaPss, &p256)
                .is_err()
        );
        let sec1_p256 = p256::SecretKey::random(&mut OsRng)
            .to_sec1_pem(LineEnding::LF)
            .unwrap();
        assert!(
            store
                .import("test-local-k1", KeyAlgorithm::Secp256k1, &sec1_p256)
                .is_err()
        );
        assert!(
            store
                .import("test-local-p256", KeyAlgorithm::P256, "not a key")
                .is_err()
        );
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn exposed_key_files_and_directories_are_refused() {
        use std::os::unix::fs::symlink;

        let store = TempStore::new("perms");
        let id = "test-local-key";
        store.init(id, KeyAlgorithm::P256, None).unwrap();

        let path = store.private_path(id);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(store.load(id).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        store.load(id).unwrap();

        fs::set_permissions(&store.dir, fs::Permissions::from_mode(0o770)).unwrap();
        assert!(store.load(id).is_err());
        assert!(store.init(id, KeyAlgorithm::P256, None).is_err());
        fs::set_permissions(&store.dir, fs::Permissions::from_mode(0o700)).unwrap();

        // A symlinked key file is not followed.
        symlink(&path, store.private_path("test-local-link")).unwrap();
        assert!(store.load("test-local-link").is_err());
    }
}
