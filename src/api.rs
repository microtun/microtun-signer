use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Json,
    body::Bytes,
    extract::{ConnectInfo, Path, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{CACHE_CONTROL, CONTENT_TYPE, PRAGMA, WWW_AUTHENTICATE},
    },
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use ulid::Ulid;

use crate::{
    auth::{AuthError, AuthPrincipal, AuthSource, Authenticator, OAuthFlowError},
    authorization::Authorizer,
    config::{KeyState, PolicyAction, valid_key_id},
    key::{KeyRing, UnlockError, UnlockOutcome},
};
use zeroize::Zeroizing;

const DEVICE_EXCHANGE_MAX_CONCURRENT: usize = 8;
const DEVICE_EXCHANGE_RATE_LIMIT: usize = 10;
const DEVICE_EXCHANGE_RATE_WINDOW: Duration = Duration::from_secs(60);
const MAX_DEVICE_EXCHANGE_SOURCES: usize = 4096;

#[derive(Clone)]
pub struct AppState {
    pub keys: Arc<KeyRing>,
    pub auth: Authenticator,
    pub authz: Authorizer,
    device_exchange_limiter: Arc<DeviceExchangeLimiter>,
}

impl AppState {
    pub fn new(keys: Arc<KeyRing>, auth: Authenticator, authz: Authorizer) -> Self {
        Self {
            keys,
            auth,
            authz,
            device_exchange_limiter: Arc::new(DeviceExchangeLimiter::new()),
        }
    }
}

struct DeviceExchangeLimiter {
    permits: Arc<Semaphore>,
    attempts: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceExchangeLimitError {
    RateLimited,
    Busy,
}

impl DeviceExchangeLimiter {
    fn new() -> Self {
        Self {
            permits: Arc::new(Semaphore::new(DEVICE_EXCHANGE_MAX_CONCURRENT)),
            attempts: Mutex::new(HashMap::new()),
        }
    }

    async fn admit(
        &self,
        source: IpAddr,
    ) -> Result<OwnedSemaphorePermit, DeviceExchangeLimitError> {
        let now = Instant::now();
        let cutoff = now.checked_sub(DEVICE_EXCHANGE_RATE_WINDOW).unwrap_or(now);
        let mut attempts = self.attempts.lock().await;

        if attempts.len() >= MAX_DEVICE_EXCHANGE_SOURCES && !attempts.contains_key(&source) {
            attempts.retain(|_, entries| {
                while entries.front().is_some_and(|attempt| *attempt <= cutoff) {
                    entries.pop_front();
                }
                !entries.is_empty()
            });
            if attempts.len() >= MAX_DEVICE_EXCHANGE_SOURCES {
                return Err(DeviceExchangeLimitError::RateLimited);
            }
        }

        let entries = attempts.entry(source).or_default();
        while entries.front().is_some_and(|attempt| *attempt <= cutoff) {
            entries.pop_front();
        }
        if entries.len() >= DEVICE_EXCHANGE_RATE_LIMIT {
            return Err(DeviceExchangeLimitError::RateLimited);
        }
        entries.push_back(now);
        drop(attempts);

        self.permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| DeviceExchangeLimitError::Busy)
    }
}

/// State for the local-only admin API served on the Unix-domain socket.
#[derive(Clone)]
pub struct AdminState {
    pub keys: Arc<KeyRing>,
    /// Allows one key decryption at a time. Each attempt runs a deliberately
    /// expensive KDF (scrypt may use up to 1 GiB), so concurrent attempts are
    /// queued rather than multiplied.
    pub unlock_permits: Arc<Semaphore>,
}

impl AdminState {
    pub fn new(keys: Arc<KeyRing>) -> Self {
        Self {
            keys,
            unlock_permits: Arc::new(Semaphore::new(1)),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct AuditRecord {
    request_id: String,
    operation: String,
    success: bool,
    reason: String,
    key_id: Option<String>,
    firmware_digest: Option<String>,
    identity_id: Option<String>,
    principal: Option<String>,
    auth_method: Option<String>,
    issuer: Option<String>,
    audience: Option<String>,
    subject: Option<String>,
    github_login: Option<String>,
    github_user_id: Option<String>,
    actor: Option<String>,
    actor_id: Option<String>,
    repository: Option<String>,
    repository_id: Option<String>,
    git_ref: Option<String>,
    ref_protected: Option<bool>,
    environment: Option<String>,
    commit_sha: Option<String>,
    event_name: Option<String>,
    workflow_ref: Option<String>,
    run_id: Option<String>,
    run_attempt: Option<String>,
    jti: Option<String>,
}

pub async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}

#[derive(Serialize)]
struct OAuthSessionResponse {
    access_token: String,
    expires_in: u64,
}

#[derive(Serialize)]
struct OAuthDeviceConfigResponse {
    client_id: String,
    device_code_url: String,
    access_token_url: String,
    scope: &'static str,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OAuthDeviceExchangeRequest {
    access_token: String,
}

/// Return the public OAuth parameters a CLI needs for GitHub's device flow.
/// No secret is exposed here: OAuth client IDs and the GitHub endpoints are
/// public, while the client secret remains in the signer process.
pub async fn github_oauth_device_config(State(state): State<AppState>) -> Response {
    let config = state.auth.github_oauth_device_config();
    let mut response = Json(OAuthDeviceConfigResponse {
        client_id: config.client_id,
        device_code_url: config.device_code_url,
        access_token_url: config.access_token_url,
        scope: config.scope,
    })
    .into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Convert a GitHub device-flow token into a short-lived signer-local session.
/// The endpoint is source-rate-limited and globally concurrency-bounded before
/// it can cause authenticated requests from the signer to GitHub.
pub async fn github_oauth_device_exchange(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let request_id = Ulid::new().to_string();
    let _admission = state
        .device_exchange_limiter
        .admit(peer.ip())
        .await
        .map_err(|error| device_exchange_limit_error(error, &request_id))?;
    if !is_json_content_type(&headers) {
        return Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-content-type",
            "Unsupported content type",
            "GitHub device-token exchanges must use Content-Type: application/json.",
            &request_id,
        ));
    }

    let request: OAuthDeviceExchangeRequest = serde_json::from_slice(&body).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "malformed-json",
            "Malformed GitHub device-token exchange",
            "The request body must contain exactly one string field named access_token.",
            &request_id,
        )
    })?;
    let access_token = Zeroizing::new(request.access_token);
    let grant = state
        .auth
        .complete_github_device_oauth(access_token.as_str())
        .await
        .map_err(|error| {
            tracing::warn!(
                target: "microtun_signer::audit",
                request_id = %request_id,
                operation = "oauth-device-login",
                success = false,
                reason = %error,
                "microtun signer login audit event"
            );
            oauth_flow_error(error, &request_id)
        })?;

    let mut response = Json(OAuthSessionResponse {
        access_token: grant.access_token,
        expires_in: grant.expires_in,
    })
    .into_response();
    let headers = response.headers_mut();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    Ok(response)
}

pub async fn get_public_key(
    State(state): State<AppState>,
    Path(key_id): Path<String>,
) -> Result<Response, ApiError> {
    let request_id = Ulid::new().to_string();
    let key = if valid_key_id(&key_id) {
        state.keys.get(&key_id)
    } else {
        None
    }
    .ok_or_else(|| {
        ApiError::new(
            StatusCode::NOT_FOUND,
            "unknown-key",
            "Unknown signing key",
            "The requested immutable signing key identifier does not exist.",
            &request_id,
        )
    })?;

    let pem = key.public_key_pem().ok_or_else(|| {
        ApiError::new(
            StatusCode::LOCKED,
            "key-locked",
            "Signing key is locked",
            "The public key becomes available after the signing key is unlocked.",
            &request_id,
        )
    })?;

    Ok(([(CONTENT_TYPE, "application/x-pem-file")], pem).into_response())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnlockRequest {
    passphrase: String,
}

pub async fn unlock_key(
    State(state): State<AdminState>,
    Path(key_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let request_id = Ulid::new().to_string();

    if !is_json_content_type(&headers) {
        return Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-content-type",
            "Unsupported content type",
            "Unlock requests must use Content-Type: application/json.",
            &request_id,
        ));
    }

    let key = if valid_key_id(&key_id) {
        state.keys.get(&key_id)
    } else {
        None
    };
    let Some(key) = key else {
        tracing::warn!(
            target: "microtun_signer::audit",
            request_id = %request_id,
            operation = "unlock-key",
            success = false,
            reason = "unknown-key",
            key_id = %key_id,
            "microtun signer unlock audit event"
        );
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "unknown-key",
            "Unknown signing key",
            "The requested immutable signing key identifier does not exist.",
            &request_id,
        ));
    };

    let request: UnlockRequest = serde_json::from_slice(&body).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "malformed-json",
            "Malformed unlock request",
            "The request body must contain a JSON string field named passphrase.",
            &request_id,
        )
    })?;
    if request.passphrase.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "empty-passphrase",
            "Signing key passphrase is empty",
            "The unlock passphrase must not be empty.",
            &request_id,
        ));
    }
    let passphrase = Zeroizing::new(request.passphrase);

    // The KDF takes hundreds of milliseconds to seconds of CPU, so it runs on
    // the blocking pool instead of stalling a runtime worker. The permit is
    // moved into the blocking task: if the client disconnects, the permit is
    // still held until the decryption actually finishes.
    let permit = state
        .unlock_permits
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| unlock_task_failed(&request_id, key.id()))?;
    let keys = state.keys.clone();
    let blocking_key_id = key.id().to_owned();
    let unlock_result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        keys.get(&blocking_key_id)
            .expect("key existence was checked before spawning")
            .unlock(passphrase.as_str())
    })
    .await
    .map_err(|_| unlock_task_failed(&request_id, key.id()))?;

    let outcome = match unlock_result {
        Ok(outcome) => outcome,
        Err(UnlockError::Inactive) => {
            tracing::warn!(
                target: "microtun_signer::audit",
                request_id = %request_id,
                operation = "unlock-key",
                success = false,
                reason = "key-not-active",
                key_id = key.id(),
                "microtun signer unlock audit event"
            );
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "key-state-conflict",
                "Signing key is not active",
                "Only active signing keys can be unlocked.",
                &request_id,
            ));
        }
        Err(UnlockError::InvalidPassphrase) => {
            tracing::warn!(
                target: "microtun_signer::audit",
                request_id = %request_id,
                operation = "unlock-key",
                success = false,
                reason = "invalid-passphrase",
                key_id = key.id(),
                "microtun signer unlock audit event"
            );
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "invalid-key-passphrase",
                "Signing key unlock failed",
                "The supplied passphrase could not unlock the encrypted signing key.",
                &request_id,
            ));
        }
        Err(UnlockError::LockPoisoned) => {
            return Err(ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "key-lock-failure",
                "Signing key lock failed",
                "The signing key could not be unlocked due to an internal state error.",
                &request_id,
            ));
        }
    };

    tracing::info!(
        target: "microtun_signer::audit",
        request_id = %request_id,
        operation = "unlock-key",
        success = true,
        reason = if outcome == UnlockOutcome::AlreadyUnlocked { "already-unlocked" } else { "ok" },
        key_id = key.id(),
        "microtun signer unlock audit event"
    );

    Ok(StatusCode::NO_CONTENT)
}

fn unlock_task_failed(request_id: &str, key_id: &str) -> ApiError {
    tracing::error!(
        target: "microtun_signer::audit",
        request_id = %request_id,
        operation = "unlock-key",
        success = false,
        reason = "unlock-task-failed",
        key_id = key_id,
        "microtun signer unlock audit event"
    );
    ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "key-unlock-failure",
        "Signing key unlock failed",
        "The signing key could not be unlocked due to an internal error.",
        request_id,
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningRequest {
    digest: String,
}

#[derive(Serialize)]
pub struct SignatureResponse {
    signature: String,
}

pub async fn create_signature(
    State(state): State<AppState>,
    Path(key_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<SignatureResponse>, ApiError> {
    let attempt_request_id = Ulid::new().to_string();

    if !is_json_content_type(&headers) {
        return Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-content-type",
            "Unsupported content type",
            "Signing requests must use Content-Type: application/json.",
            &attempt_request_id,
        ));
    }

    let principal = match state.auth.authenticate(&headers).await {
        Ok(principal) => principal,
        Err(error) => {
            let api_error = auth_error(error, &attempt_request_id);
            audit_best_effort(
                &state,
                AuditRecord {
                    request_id: attempt_request_id.clone(),
                    operation: "sign".into(),
                    success: false,
                    reason: api_error.slug.to_owned(),
                    ..AuditRecord::default()
                },
            )
            .await;
            return Err(api_error);
        }
    };

    let request: SigningRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => {
            let error = ApiError::new(
                StatusCode::BAD_REQUEST,
                "malformed-json",
                "Malformed signing request",
                "The request body must contain exactly one base64-encoded SHA-256 digest.",
                &attempt_request_id,
            );
            audit_best_effort(
                &state,
                audit_record(
                    &attempt_request_id,
                    "sign",
                    false,
                    error.slug,
                    Some(&principal),
                    AuditDetails {
                        key_id: Some(&key_id),
                        ..AuditDetails::default()
                    },
                ),
            )
            .await;
            return Err(error);
        }
    };

    let digest = match validate_signing_request(&state, &principal, &key_id, request) {
        Ok(digest) => digest,
        Err(mut error) => {
            error.request_id = attempt_request_id.clone();
            audit_best_effort(
                &state,
                audit_record(
                    &attempt_request_id,
                    "sign",
                    false,
                    error.slug,
                    Some(&principal),
                    AuditDetails {
                        key_id: Some(&key_id),
                        ..AuditDetails::default()
                    },
                ),
            )
            .await;
            return Err(error);
        }
    };

    let key = state
        .keys
        .get(&key_id)
        .expect("validated key must remain present in immutable keyring");
    let firmware_digest = hex::encode(digest);
    let signature = key.sign_digest(&digest).ok_or_else(|| {
        ApiError::new(
            StatusCode::LOCKED,
            "key-locked",
            "Signing key is locked",
            "The requested signing key must be manually unlocked before it can create signatures.",
            &attempt_request_id,
        )
    })?;

    audit_best_effort(
        &state,
        audit_record(
            &attempt_request_id,
            "sign",
            true,
            "ok",
            Some(&principal),
            AuditDetails {
                key_id: Some(&key_id),
                firmware_digest: Some(&firmware_digest),
            },
        ),
    )
    .await;

    Ok(Json(SignatureResponse {
        signature: BASE64.encode(signature),
    }))
}

fn validate_signing_request(
    state: &AppState,
    principal: &AuthPrincipal,
    key_id: &str,
    request: SigningRequest,
) -> Result<[u8; 32], ApiError> {
    if !valid_key_id(key_id) {
        return Err(unknown_key_error());
    }
    state
        .authz
        .authorize(principal, PolicyAction::Sign, key_id)
        .map_err(|_| policy_denied_error())?;

    let Some(key) = state.keys.get(key_id) else {
        return Err(unknown_key_error());
    };
    if key.state() != KeyState::Active {
        return Err(ApiError::without_request_id(
            StatusCode::CONFLICT,
            "key-state-conflict",
            "Signing key is not active",
            "The requested key is available for metadata lookup but cannot create new signatures.",
        ));
    }
    if !key.is_unlocked() {
        return Err(ApiError::without_request_id(
            StatusCode::LOCKED,
            "key-locked",
            "Signing key is locked",
            "The requested signing key must be manually unlocked before it can create signatures.",
        ));
    }

    let decoded = BASE64.decode(request.digest.as_bytes()).map_err(|_| {
        ApiError::unprocessable(
            "invalid-digest-base64",
            "Invalid firmware digest",
            "digest must be valid base64.",
        )
    })?;
    let digest: [u8; 32] = decoded.try_into().map_err(|bytes: Vec<u8>| {
        ApiError::unprocessable(
            "invalid-digest-length",
            "Invalid firmware digest length",
            if bytes.len() < 32 {
                "The decoded SHA-256 digest is shorter than 32 bytes."
            } else {
                "The decoded SHA-256 digest is longer than 32 bytes."
            },
        )
    })?;

    validate_signing_context(principal)?;
    Ok(digest)
}

fn unknown_key_error() -> ApiError {
    ApiError::without_request_id(
        StatusCode::NOT_FOUND,
        "unknown-key",
        "Unknown signing key",
        "The requested immutable signing key identifier does not exist.",
    )
}

fn validate_signing_context(principal: &AuthPrincipal) -> Result<(), ApiError> {
    let AuthSource::GithubActions(actions) = &principal.source else {
        return Ok(());
    };

    if actions.ref_type != "tag" {
        return Err(ApiError::without_request_id(
            StatusCode::FORBIDDEN,
            "tag-required",
            "A release tag is required",
            "Firmware signing from GitHub Actions requires an authenticated tag ref.",
        ));
    }

    // Anyone who can push a tag controls the workflow file at that tag. Only
    // accept tags that GitHub reports as protected by a ruleset, so that
    // creating a release tag is itself a privileged operation.
    if !actions.ref_protected {
        return Err(ApiError::without_request_id(
            StatusCode::FORBIDDEN,
            "protected-ref-required",
            "A protected release tag is required",
            "Firmware signing from GitHub Actions requires a tag protected by a GitHub ruleset.",
        ));
    }

    let Some(tag) = actions.git_ref.strip_prefix("refs/tags/") else {
        return Err(ApiError::without_request_id(
            StatusCode::FORBIDDEN,
            "tag-required",
            "A release tag is required",
            "The authenticated GitHub Actions ref must be under refs/tags/.",
        ));
    };
    if tag.is_empty() {
        return Err(ApiError::without_request_id(
            StatusCode::FORBIDDEN,
            "tag-required",
            "A release tag is required",
            "The authenticated GitHub Actions tag ref must name a tag.",
        ));
    }

    Ok(())
}

fn is_json_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
}

fn oauth_flow_error(error: OAuthFlowError, request_id: &str) -> ApiError {
    match error {
        OAuthFlowError::TokenValidationFailed => ApiError::new(
            StatusCode::UNAUTHORIZED,
            "oauth-token-invalid",
            "GitHub OAuth token is invalid",
            "The token is invalid or was not issued to this signer's GitHub OAuth application.",
            request_id,
        ),
        OAuthFlowError::TokenReplayed => ApiError::new(
            StatusCode::CONFLICT,
            "oauth-token-replayed",
            "GitHub OAuth token has already been used",
            "Start a new GitHub device authorization and try again.",
            request_id,
        ),
        OAuthFlowError::ReplayCacheUnavailable => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "oauth-replay-cache-unavailable",
            "GitHub OAuth login is temporarily unavailable",
            "The signer cannot safely record the one-time bootstrap token.",
            request_id,
        ),
        OAuthFlowError::ScopeNotGranted => ApiError::new(
            StatusCode::FORBIDDEN,
            "oauth-scope-not-granted",
            "GitHub did not grant the read:user scope",
            "The read:user scope is required to verify two-factor authentication.",
            request_id,
        ),
        OAuthFlowError::IdentityProviderUnavailable => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "identity-provider-unavailable",
            "GitHub identity verification is temporarily unavailable",
            "The signer could not complete GitHub OAuth authentication.",
            request_id,
        ),
        OAuthFlowError::TokenRevocationFailed => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "oauth-token-revocation-failed",
            "GitHub OAuth token revocation failed",
            "The signer will not issue a local session until the GitHub bootstrap token is revoked.",
            request_id,
        ),
        OAuthFlowError::ClaimsDenied => ApiError::new(
            StatusCode::FORBIDDEN,
            "identity-not-authorized",
            "Authenticated identity is not authorized",
            "The authenticated GitHub account is not configured as a signer identity.",
            request_id,
        ),
        OAuthFlowError::TwoFactorRequired => ApiError::new(
            StatusCode::FORBIDDEN,
            "github-2fa-required",
            "GitHub two-factor authentication is required",
            "Enable two-factor authentication on the GitHub account and log in again.",
            request_id,
        ),
        OAuthFlowError::SessionCapacity => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "oauth-capacity-exhausted",
            "GitHub OAuth login is temporarily unavailable",
            "The signer has reached its temporary OAuth session capacity.",
            request_id,
        ),
    }
}

fn device_exchange_limit_error(error: DeviceExchangeLimitError, request_id: &str) -> ApiError {
    match error {
        DeviceExchangeLimitError::RateLimited => ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "oauth-device-rate-limited",
            "Too many GitHub device-token exchanges",
            "Wait before attempting another GitHub device-token exchange from this source.",
            request_id,
        ),
        DeviceExchangeLimitError::Busy => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "oauth-device-busy",
            "GitHub device-token exchange is busy",
            "The signer is already processing the maximum number of GitHub device-token exchanges.",
            request_id,
        ),
    }
}

fn auth_error(error: AuthError, request_id: &str) -> ApiError {
    match error {
        AuthError::ClaimsDenied => ApiError::new(
            StatusCode::FORBIDDEN,
            "identity-not-authorized",
            "Authenticated identity is not authorized",
            "The authenticated GitHub identity does not satisfy the signer requirements.",
            request_id,
        ),
        AuthError::KeyDiscovery => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "oidc-key-discovery-unavailable",
            "OIDC verification is temporarily unavailable",
            "The signer could not refresh the GitHub Actions OIDC verification keys.",
            request_id,
        ),
        AuthError::IdentityProviderUnavailable => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "identity-provider-unavailable",
            "GitHub identity verification is temporarily unavailable",
            "The signer could not verify the GitHub account credential.",
            request_id,
        ),
        AuthError::ReplayCacheUnavailable => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "oidc-replay-cache-unavailable",
            "OIDC replay protection is temporarily unavailable",
            "The signer could not record the GitHub Actions token as used.",
            request_id,
        ),
        AuthError::TokenReplayed => {
            let mut error = ApiError::unauthorized(request_id);
            error.slug = "token-replayed";
            error
        }
        AuthError::MissingBearer | AuthError::TokenTooLarge | AuthError::InvalidToken => {
            ApiError::unauthorized(request_id)
        }
    }
}

fn policy_denied_error() -> ApiError {
    ApiError::without_request_id(
        StatusCode::FORBIDDEN,
        "policy-denied",
        "Identity policy denied this operation",
        "The authenticated identity is not allowed to perform this action with the requested key.",
    )
}

#[derive(Default)]
struct AuditDetails<'a> {
    key_id: Option<&'a str>,
    firmware_digest: Option<&'a str>,
}

fn audit_record(
    request_id: &str,
    operation: &str,
    success: bool,
    reason: &str,
    principal: Option<&AuthPrincipal>,
    details: AuditDetails<'_>,
) -> AuditRecord {
    let account = principal.and_then(|principal| match &principal.source {
        AuthSource::GithubAccount(account) => Some(account),
        AuthSource::GithubActions(_) => None,
    });
    let actions = principal.and_then(|principal| match &principal.source {
        AuthSource::GithubAccount(_) => None,
        AuthSource::GithubActions(actions) => Some(actions),
    });
    AuditRecord {
        request_id: request_id.to_owned(),
        operation: operation.to_owned(),
        success,
        reason: reason.to_owned(),
        key_id: details.key_id.map(str::to_owned),
        firmware_digest: details.firmware_digest.map(str::to_owned),
        identity_id: principal.map(|principal| principal.identity_id.clone()),
        principal: principal.map(|principal| principal.principal_key.clone()),
        auth_method: principal.map(|principal| principal.auth_method.to_owned()),
        issuer: principal.map(|principal| principal.issuer.clone()),
        audience: principal.and_then(|principal| principal.audience.clone()),
        subject: principal.map(|principal| principal.subject.clone()),
        github_login: account.map(|identity| identity.login.clone()),
        github_user_id: account.map(|identity| identity.user_id.clone()),
        actor: actions.and_then(|identity| identity.actor.clone()),
        actor_id: actions.and_then(|identity| identity.actor_id.clone()),
        repository: actions.map(|identity| identity.repository.clone()),
        repository_id: actions.map(|identity| identity.repository_id.clone()),
        git_ref: actions.map(|identity| identity.git_ref.clone()),
        ref_protected: actions.map(|identity| identity.ref_protected),
        environment: actions.and_then(|identity| identity.environment.clone()),
        commit_sha: actions.map(|identity| identity.sha.clone()),
        event_name: actions.map(|identity| identity.event_name.clone()),
        workflow_ref: actions.map(|identity| identity.workflow_ref.clone()),
        run_id: actions.map(|identity| identity.run_id.clone()),
        run_attempt: actions.map(|identity| identity.run_attempt.clone()),
        jti: principal.and_then(|principal| principal.jti.clone()),
    }
}

async fn audit_best_effort(_state: &AppState, record: AuditRecord) {
    tracing::info!(
        target: "microtun_signer::audit",
        request_id = %record.request_id,
        operation = %record.operation,
        success = record.success,
        reason = %record.reason,
        key_id = record.key_id.as_deref().unwrap_or(""),
        firmware_digest = record.firmware_digest.as_deref().unwrap_or(""),
        identity_id = record.identity_id.as_deref().unwrap_or(""),
        principal = record.principal.as_deref().unwrap_or(""),
        auth_method = record.auth_method.as_deref().unwrap_or(""),
        issuer = record.issuer.as_deref().unwrap_or(""),
        audience = record.audience.as_deref().unwrap_or(""),
        subject = record.subject.as_deref().unwrap_or(""),
        github_login = record.github_login.as_deref().unwrap_or(""),
        github_user_id = record.github_user_id.as_deref().unwrap_or(""),
        actor = record.actor.as_deref().unwrap_or(""),
        actor_id = record.actor_id.as_deref().unwrap_or(""),
        repository = record.repository.as_deref().unwrap_or(""),
        repository_id = record.repository_id.as_deref().unwrap_or(""),
        git_ref = record.git_ref.as_deref().unwrap_or(""),
        ref_protected = record.ref_protected.unwrap_or(false),
        environment = record.environment.as_deref().unwrap_or(""),
        commit_sha = record.commit_sha.as_deref().unwrap_or(""),
        event_name = record.event_name.as_deref().unwrap_or(""),
        workflow_ref = record.workflow_ref.as_deref().unwrap_or(""),
        run_id = record.run_id.as_deref().unwrap_or(""),
        run_attempt = record.run_attempt.as_deref().unwrap_or(""),
        jti = record.jti.as_deref().unwrap_or(""),
        "microtun signer audit event"
    );
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: &'static str,
    request_id: String,
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    slug: &'static str,
    request_id: String,
    authenticate: bool,
}

impl ApiError {
    fn new(
        status: StatusCode,
        slug: &'static str,
        _title: &'static str,
        _detail: &'static str,
        request_id: &str,
    ) -> Self {
        Self {
            status,
            slug,
            request_id: request_id.to_owned(),
            authenticate: false,
        }
    }

    fn without_request_id(
        status: StatusCode,
        slug: &'static str,
        title: &'static str,
        detail: &'static str,
    ) -> Self {
        Self::new(status, slug, title, detail, "")
    }

    fn unprocessable(slug: &'static str, title: &'static str, detail: &'static str) -> Self {
        Self::without_request_id(StatusCode::UNPROCESSABLE_ENTITY, slug, title, detail)
    }

    fn unauthorized(request_id: &str) -> Self {
        let mut error = Self::new(
            StatusCode::UNAUTHORIZED,
            "authentication-required",
            "Authentication required",
            "A signer OAuth session or GitHub Actions OIDC bearer credential is required.",
            request_id,
        );
        error.authenticate = true;
        error
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorBody {
            error: self.slug,
            request_id: self.request_id,
        };
        let mut response = (self.status, Json(body)).into_response();
        if self.authenticate {
            response.headers_mut().insert(
                WWW_AUTHENTICATE,
                "Bearer".parse().expect("valid authenticate header"),
            );
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthSource, GithubAccountIdentity, GithubActionsIdentity};

    #[test]
    fn oauth_device_exchange_accepts_only_access_token() {
        let request: OAuthDeviceExchangeRequest =
            serde_json::from_str(r#"{"access_token":"gho_test"}"#).unwrap();
        assert_eq!(request.access_token, "gho_test");
        let with_extra = r#"{"access_token":"gho_test","unexpected":"x"}"#;
        assert!(serde_json::from_str::<OAuthDeviceExchangeRequest>(with_extra).is_err());
    }

    #[tokio::test]
    async fn device_exchange_rate_limiter_caps_each_peer() {
        let limiter = DeviceExchangeLimiter::new();
        let source: IpAddr = "127.0.0.1".parse().unwrap();
        for _ in 0..DEVICE_EXCHANGE_RATE_LIMIT {
            drop(limiter.admit(source).await.unwrap());
        }
        assert_eq!(
            limiter.admit(source).await.unwrap_err(),
            DeviceExchangeLimitError::RateLimited
        );
    }

    #[tokio::test]
    async fn device_exchange_limiter_rejects_excess_concurrency() {
        let limiter = DeviceExchangeLimiter::new();
        let source: IpAddr = "127.0.0.1".parse().unwrap();
        let mut permits = Vec::new();
        for _ in 0..DEVICE_EXCHANGE_MAX_CONCURRENT {
            permits.push(limiter.admit(source).await.unwrap());
        }
        assert_eq!(
            limiter.admit(source).await.unwrap_err(),
            DeviceExchangeLimitError::Busy
        );
        permits.pop();
        assert!(limiter.admit(source).await.is_ok());
    }

    #[test]
    fn signing_request_accepts_only_digest() {
        let request: SigningRequest = serde_json::from_str(r#"{"digest":"AA=="}"#).unwrap();
        assert_eq!(request.digest, "AA==");
        assert!(
            serde_json::from_str::<SigningRequest>(r#"{"digest":"AA==","unexpected":"x"}"#)
                .is_err()
        );
    }

    fn actions_principal(git_ref: &str, ref_type: &str) -> AuthPrincipal {
        AuthPrincipal {
            identity_id: "release-actions".into(),
            principal_key: "github-actions:repository:123".into(),
            auth_method: "github-actions-oidc",
            issuer: "issuer".into(),
            audience: Some("aud".into()),
            subject: "subject".into(),
            jti: None,
            source: AuthSource::GithubActions(Box::new(GithubActionsIdentity {
                repository: "owner/repo".into(),
                repository_id: "123".into(),
                actor: Some("user".into()),
                actor_id: Some("456".into()),
                git_ref: git_ref.into(),
                ref_type: ref_type.into(),
                ref_protected: true,
                sha: "abcdef".into(),
                workflow_ref: "owner/repo/.github/workflows/release.yml@refs/tags/v1.2.3".into(),
                event_name: "push".into(),
                environment: Some("firmware-signing".into()),
                run_id: "42".into(),
                run_attempt: "1".into(),
            })),
        }
    }

    #[test]
    fn actions_signing_accepts_an_authenticated_tag_without_parsing_it_as_a_version() {
        let principal = actions_principal("refs/tags/release-candidate", "tag");
        assert!(validate_signing_context(&principal).is_ok());
    }

    #[test]
    fn actions_signing_requires_a_protected_tag() {
        let mut principal = actions_principal("refs/tags/v1.2.3", "tag");
        let AuthSource::GithubActions(actions) = &mut principal.source else {
            unreachable!()
        };
        actions.ref_protected = false;
        let error = validate_signing_context(&principal).unwrap_err();
        assert_eq!(error.slug, "protected-ref-required");
    }

    #[test]
    fn actions_signing_requires_an_authenticated_release_tag() {
        let principal = actions_principal("refs/heads/main", "branch");
        assert!(validate_signing_context(&principal).is_err());
    }

    #[test]
    fn human_signing_has_no_release_metadata_requirement() {
        let principal = AuthPrincipal {
            identity_id: "maintainer".into(),
            principal_key: "github-account:42".into(),
            auth_method: "github-oauth-session",
            issuer: "issuer".into(),
            audience: None,
            subject: "42".into(),
            jti: None,
            source: AuthSource::GithubAccount(GithubAccountIdentity {
                user_id: "42".into(),
                login: "octocat".into(),
            }),
        };

        assert!(validate_signing_context(&principal).is_ok());
    }

    fn admin_state() -> AdminState {
        let keys = KeyRing::from_keys_for_tests(vec![crate::key::KeyMaterial::from_pem_for_tests(
            "prod",
            include_str!("../tests/fixtures/test-ed25519-scrypt.pem"),
        )]);
        AdminState::new(Arc::new(keys))
    }

    fn unlock_request(passphrase: &str) -> (HeaderMap, Bytes) {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let body = serde_json::to_vec(&serde_json::json!({ "passphrase": passphrase })).unwrap();
        (headers, Bytes::from(body))
    }

    /// On a single-threaded runtime, a KDF running inline would starve every
    /// other task until it finished. Here a ticker keeps running throughout.
    #[tokio::test(flavor = "current_thread")]
    async fn unlock_kdf_does_not_block_the_async_runtime() {
        let state = admin_state();
        let ticks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let ticker = {
            let ticks = ticks.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                    ticks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            })
        };

        let started = std::time::Instant::now();
        let (headers, body) = unlock_request("test-passphrase");
        let status = unlock_key(State(state.clone()), Path("prod".into()), headers, body)
            .await
            .unwrap();
        let elapsed = started.elapsed();
        ticker.abort();

        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(state.keys.get("prod").unwrap().is_unlocked());
        let ticks = ticks.load(std::sync::atomic::Ordering::Relaxed);
        // Expect roughly one tick per 5 ms of KDF time; demand at least a third.
        let expected = elapsed.as_millis() as usize / 15;
        assert!(
            ticks >= expected.max(1),
            "runtime starved: {ticks} ticks during {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn wrong_passphrase_is_rejected_through_the_blocking_path() {
        let state = admin_state();
        let (headers, body) = unlock_request("wrong");
        let error = unlock_key(State(state.clone()), Path("prod".into()), headers, body)
            .await
            .unwrap_err();
        assert_eq!(error.slug, "invalid-key-passphrase");
        assert!(!state.keys.get("prod").unwrap().is_unlocked());
        // The permit was released, so a later attempt can proceed.
        assert_eq!(state.unlock_permits.available_permits(), 1);
    }
}
