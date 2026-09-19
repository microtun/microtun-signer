use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use thiserror::Error;

use crate::key::KeyMaterial;

#[derive(Clone)]
pub struct Database {
    path: Arc<PathBuf>,
    idempotency_ttl: Duration,
}

#[derive(Debug)]
pub struct SignDecision {
    pub request_id: String,
    pub signature: [u8; 64],
    pub replayed: bool,
}

#[derive(Debug, Error)]
pub enum SignStoreError {
    #[error("idempotency key was reused with a different request body")]
    IdempotencyConflict,
    #[error("this key/board/version is already bound to a different firmware digest")]
    VersionConflict,
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("stored signature has an invalid length")]
    InvalidStoredSignature,
}

#[derive(Debug, Clone, Default)]
pub struct AuditRecord {
    pub request_id: String,
    pub operation: String,
    pub success: bool,
    pub reason: String,
    pub key_id: Option<String>,
    pub key_fingerprint: Option<String>,
    pub message_sha256: Option<String>,
    pub principal: Option<String>,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub subject: Option<String>,
    pub repository_id: Option<String>,
    pub git_ref: Option<String>,
    pub workflow_ref: Option<String>,
    pub run_id: Option<String>,
    pub run_attempt: Option<String>,
    pub jti: Option<String>,
    pub board: Option<String>,
    pub version: Option<String>,
}

impl Database {
    pub fn new(path: PathBuf, idempotency_ttl_hours: u64) -> Self {
        Self {
            path: Arc::new(path),
            idempotency_ttl: Duration::from_secs(idempotency_ttl_hours * 60 * 60),
        }
    }

    pub fn init(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            let existed = parent.exists();
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create database directory {}", parent.display())
            })?;
            if !existed {
                tighten_directory_permissions(parent)?;
            }
        }
        let connection = self.connect().context("failed to open signing database")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS key_registry (
                key_id TEXT PRIMARY KEY,
                fingerprint TEXT NOT NULL,
                public_key_pem TEXT NOT NULL,
                first_seen_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS idempotency (
                principal TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                request_hash BLOB NOT NULL,
                request_id TEXT NOT NULL,
                signature BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (principal, idempotency_key)
            );

            CREATE TABLE IF NOT EXISTS release_ledger (
                key_id TEXT NOT NULL,
                board TEXT NOT NULL,
                version TEXT NOT NULL,
                digest BLOB NOT NULL,
                first_request_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (key_id, board, version)
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at INTEGER NOT NULL,
                request_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                success INTEGER NOT NULL,
                reason TEXT NOT NULL,
                key_id TEXT,
                key_fingerprint TEXT,
                message_sha256 TEXT,
                principal TEXT,
                issuer TEXT,
                audience TEXT,
                subject TEXT,
                repository_id TEXT,
                git_ref TEXT,
                workflow_ref TEXT,
                run_id TEXT,
                run_attempt TEXT,
                jti TEXT,
                board TEXT,
                version TEXT
            );

            CREATE INDEX IF NOT EXISTS audit_log_request_id_idx ON audit_log(request_id);
            CREATE INDEX IF NOT EXISTS audit_log_created_at_idx ON audit_log(created_at);
            "#,
        )?;
        tighten_file_permissions(&self.path)?;
        Ok(())
    }

    pub fn register_key(
        &self,
        key_id: &str,
        fingerprint: &str,
        public_key_pem: &str,
    ) -> Result<()> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<String> = transaction
            .query_row(
                "SELECT fingerprint FROM key_registry WHERE key_id = ?1",
                [key_id],
                |row| row.get(0),
            )
            .optional()?;

        if let Some(stored_fingerprint) = existing {
            if stored_fingerprint != fingerprint {
                bail!(
                    "immutable key id {key_id:?} was previously registered with different key material"
                );
            }
        } else {
            transaction.execute(
                "INSERT INTO key_registry (key_id, fingerprint, public_key_pem, first_seen_at) VALUES (?1, ?2, ?3, ?4)",
                params![key_id, fingerprint, public_key_pem, unix_timestamp()],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn sign_or_replay(
        &self,
        principal: &str,
        idempotency_key: &str,
        request_hash: &[u8; 32],
        key_id: &str,
        board: &str,
        version: &str,
        digest: &[u8; 32],
        candidate_request_id: &str,
        key: &KeyMaterial,
    ) -> Result<SignDecision, SignStoreError> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = unix_timestamp();
        let expiry = now.saturating_sub(self.idempotency_ttl.as_secs() as i64);
        transaction.execute("DELETE FROM idempotency WHERE created_at < ?1", [expiry])?;

        let existing: Option<(Vec<u8>, String, Vec<u8>)> = transaction
            .query_row(
                "SELECT request_hash, request_id, signature FROM idempotency WHERE principal = ?1 AND idempotency_key = ?2",
                params![principal, idempotency_key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if let Some((stored_hash, request_id, stored_signature)) = existing {
            if stored_hash.as_slice() != request_hash {
                return Err(SignStoreError::IdempotencyConflict);
            }
            let signature: [u8; 64] = stored_signature
                .try_into()
                .map_err(|_| SignStoreError::InvalidStoredSignature)?;
            transaction.commit()?;
            return Ok(SignDecision {
                request_id,
                signature,
                replayed: true,
            });
        }

        let existing_digest: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT digest FROM release_ledger WHERE key_id = ?1 AND board = ?2 AND version = ?3",
                params![key_id, board, version],
                |row| row.get(0),
            )
            .optional()?;
        if existing_digest
            .as_deref()
            .is_some_and(|stored| stored != digest)
        {
            return Err(SignStoreError::VersionConflict);
        }

        let signature = key.sign_digest(digest);
        transaction.execute(
            "INSERT OR IGNORE INTO release_ledger (key_id, board, version, digest, first_request_id, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![key_id, board, version, digest.as_slice(), candidate_request_id, now],
        )?;
        transaction.execute(
            "INSERT INTO idempotency (principal, idempotency_key, request_hash, request_id, signature, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                principal,
                idempotency_key,
                request_hash.as_slice(),
                candidate_request_id,
                signature.as_slice(),
                now
            ],
        )?;
        transaction.commit()?;

        Ok(SignDecision {
            request_id: candidate_request_id.to_owned(),
            signature,
            replayed: false,
        })
    }

    pub fn record_audit(&self, record: &AuditRecord) -> Result<()> {
        let connection = self.connect()?;
        connection.execute(
            r#"
            INSERT INTO audit_log (
                created_at, request_id, operation, success, reason, key_id, key_fingerprint,
                message_sha256, principal, issuer, audience, subject, repository_id, git_ref,
                workflow_ref, run_id, run_attempt, jti, board, version
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20
            )
            "#,
            params![
                unix_timestamp(),
                &record.request_id,
                &record.operation,
                record.success as i64,
                &record.reason,
                record.key_id.as_deref(),
                record.key_fingerprint.as_deref(),
                record.message_sha256.as_deref(),
                record.principal.as_deref(),
                record.issuer.as_deref(),
                record.audience.as_deref(),
                record.subject.as_deref(),
                record.repository_id.as_deref(),
                record.git_ref.as_deref(),
                record.workflow_ref.as_deref(),
                record.run_id.as_deref(),
                record.run_attempt.as_deref(),
                record.jti.as_deref(),
                record.board.as_deref(),
                record.version.as_deref(),
            ],
        )?;
        Ok(())
    }

    fn connect(&self) -> rusqlite::Result<Connection> {
        let connection = Connection::open(self.path.as_ref())?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        Ok(connection)
    }
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(unix)]
fn tighten_directory_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn tighten_directory_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn tighten_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn tighten_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}
