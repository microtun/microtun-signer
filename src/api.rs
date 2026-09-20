use std::sync::Arc;

use axum::{
    Json,
    body::Bytes,
    extract::{Path, Query, State},
    http::{
        HeaderMap, StatusCode,
        header::{CACHE_CONTROL, CONTENT_TYPE, PRAGMA, WWW_AUTHENTICATE},
    },
    response::{IntoResponse, Redirect, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ulid::Ulid;

use crate::{
    auth::{AuthError, AuthPrincipal, AuthSource, Authenticator, OAuthFlowError},
    authorization::Authorizer,
    config::{KeyState, PolicyAction, valid_key_id},
    key::{KeyMaterial, KeyRing, UnlockError, UnlockOutcome},
};
use zeroize::Zeroizing;

pub const API_VERSION: &str = "microtun-signing/v1";
const KEY_PURPOSE: &str = "microtun-firmware";
const KEY_ALGORITHM: &str = "ed25519";
const KEY_FORMAT: &str = "spki-pem";
const SIGNATURE_ALGORITHM: &str = "ed25519";
const MESSAGE_TYPE: &str = "mcuboot-sha256";

#[derive(Clone)]
pub struct AppState {
    pub keys: Arc<KeyRing>,
    pub auth: Authenticator,
    pub authz: Authorizer,
}

#[derive(Clone)]
pub struct UnlockState {
    pub keys: Arc<KeyRing>,
}

#[derive(Debug, Clone, Default)]
struct AuditRecord {
    request_id: String,
    operation: String,
    success: bool,
    reason: String,
    key_id: Option<String>,
    key_fingerprint: Option<String>,
    message_sha256: Option<String>,
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
    repository_id: Option<String>,
    git_ref: Option<String>,
    workflow_ref: Option<String>,
    run_id: Option<String>,
    run_attempt: Option<String>,
    jti: Option<String>,
    board: Option<String>,
    version: Option<String>,
}

#[derive(Serialize)]
pub struct HealthResponse {
    status: &'static str,
}

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

#[derive(Debug, Deserialize)]
pub struct GithubOAuthCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(Serialize)]
struct OAuthSessionResponse {
    token_type: &'static str,
    access_token: String,
    expires_in: u64,
    identity: OAuthIdentityResponse,
}

#[derive(Serialize)]
struct OAuthIdentityResponse {
    id: String,
    kind: &'static str,
    github_user_id: String,
    github_login: String,
}

/// Redirect a human user to GitHub to authorize this signer OAuth application.
pub async fn github_oauth_login(State(state): State<AppState>) -> Result<Redirect, ApiError> {
    let request_id = Ulid::new().to_string();
    let url = state
        .auth
        .github_oauth_authorize_url()
        .await
        .map_err(|error| oauth_flow_error(error, &request_id))?;
    Ok(Redirect::temporary(&url))
}

/// GitHub OAuth callback. The signer exchanges the one-time GitHub code using
/// its own client secret, maps the account to a configured identity, and mints
/// a short-lived signer-local bearer credential. The GitHub token is not
/// returned to the caller.
pub async fn github_oauth_callback(
    State(state): State<AppState>,
    Query(query): Query<GithubOAuthCallbackQuery>,
) -> Result<Response, ApiError> {
    let request_id = Ulid::new().to_string();
    if query.error.is_some() {
        return Err(oauth_flow_error(
            OAuthFlowError::AuthorizationDenied,
            &request_id,
        ));
    }
    let code = query
        .code
        .as_deref()
        .ok_or_else(|| oauth_flow_error(OAuthFlowError::AuthorizationDenied, &request_id))?;
    let oauth_state = query
        .state
        .as_deref()
        .ok_or_else(|| oauth_flow_error(OAuthFlowError::InvalidState, &request_id))?;

    let grant = state
        .auth
        .complete_github_oauth(code, oauth_state)
        .await
        .map_err(|error| oauth_flow_error(error, &request_id))?;

    let mut response = Json(OAuthSessionResponse {
        token_type: "Bearer",
        access_token: grant.access_token,
        expires_in: grant.expires_in,
        identity: OAuthIdentityResponse {
            id: grant.identity_id,
            kind: "github-account",
            github_user_id: grant.user_id,
            github_login: grant.login,
        },
    })
    .into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, "no-store".parse().expect("valid header"));
    response
        .headers_mut()
        .insert(PRAGMA, "no-cache".parse().expect("valid header"));
    Ok(response)
}

#[derive(Serialize)]
pub struct KeyResponse {
    api_version: &'static str,
    key: KeyResponseBody,
}

#[derive(Serialize)]
struct KeyResponseBody {
    id: String,
    purpose: &'static str,
    algorithm: &'static str,
    state: &'static str,
    lock_state: &'static str,
    public_key: Option<PublicKeyResponse>,
}

#[derive(Serialize)]
struct PublicKeyResponse {
    format: &'static str,
    value: String,
    fingerprint: String,
}

pub async fn get_key(
    State(state): State<AppState>,
    Path(key_id): Path<String>,
) -> Result<Response, ApiError> {
    let request_id = Ulid::new().to_string();

    let key = if valid_key_id(&key_id) {
        state.keys.get(&key_id)
    } else {
        None
    };
    let Some(key) = key else {
        let error = ApiError::new(
            StatusCode::NOT_FOUND,
            "unknown-key",
            "Unknown signing key",
            "The requested immutable signing key identifier does not exist.",
            &request_id,
        );
        audit_best_effort(
            &state,
            audit_record(
                &request_id,
                "get-key",
                false,
                error.title,
                None,
                AuditDetails {
                    key_id: Some(&key_id),
                    ..AuditDetails::default()
                },
            ),
        )
        .await;
        return Err(error);
    };

    let fingerprint = key.fingerprint();
    let response = KeyResponse {
        api_version: API_VERSION,
        key: key_response_body(key),
    };

    audit_best_effort(
        &state,
        audit_record(
            &request_id,
            "get-key",
            true,
            "ok",
            None,
            AuditDetails {
                key_id: Some(key.id()),
                fingerprint: fingerprint.as_deref(),
                ..AuditDetails::default()
            },
        ),
    )
    .await;
    let mut response = Json(response).into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, "no-store".parse().expect("valid header"));
    Ok(response)
}

fn key_response_body(key: &KeyMaterial) -> KeyResponseBody {
    let public_key = key
        .public_key_pem()
        .zip(key.fingerprint())
        .map(|(value, fingerprint)| PublicKeyResponse {
            format: KEY_FORMAT,
            value,
            fingerprint,
        });
    KeyResponseBody {
        id: key.id().to_owned(),
        purpose: KEY_PURPOSE,
        algorithm: KEY_ALGORITHM,
        state: key.state().as_str(),
        lock_state: if key.is_unlocked() {
            "unlocked"
        } else {
            "locked"
        },
        public_key,
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnlockRequest {
    passphrase: String,
}

#[derive(Serialize)]
pub struct UnlockResponse {
    api_version: &'static str,
    request_id: String,
    already_unlocked: bool,
    key: KeyResponseBody,
}

pub async fn unlock_key(
    State(state): State<UnlockState>,
    Path(key_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
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
            target: "microtun_firmware_signer::audit",
            request_id = %request_id,
            operation = "unlock-key",
            success = false,
            reason = "unknown-key",
            key_id = %key_id,
            "firmware signer unlock audit event"
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

    let outcome = match key.unlock(passphrase.as_str()) {
        Ok(outcome) => outcome,
        Err(UnlockError::Inactive) => {
            tracing::warn!(
                target: "microtun_firmware_signer::audit",
                request_id = %request_id,
                operation = "unlock-key",
                success = false,
                reason = "key-not-active",
                key_id = key.id(),
                "firmware signer unlock audit event"
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
                target: "microtun_firmware_signer::audit",
                request_id = %request_id,
                operation = "unlock-key",
                success = false,
                reason = "invalid-passphrase",
                key_id = key.id(),
                "firmware signer unlock audit event"
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

    let fingerprint = key.fingerprint().unwrap_or_default();
    tracing::info!(
        target: "microtun_firmware_signer::audit",
        request_id = %request_id,
        operation = "unlock-key",
        success = true,
        reason = if outcome == UnlockOutcome::AlreadyUnlocked { "already-unlocked" } else { "ok" },
        key_id = key.id(),
        key_fingerprint = %fingerprint,
        "firmware signer unlock audit event"
    );

    let mut response = Json(UnlockResponse {
        api_version: API_VERSION,
        request_id,
        already_unlocked: outcome == UnlockOutcome::AlreadyUnlocked,
        key: key_response_body(key),
    })
    .into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, "no-store".parse().expect("valid header"));
    response
        .headers_mut()
        .insert(PRAGMA, "no-cache".parse().expect("valid header"));
    Ok(response)
}

#[derive(Debug, Deserialize)]
struct SigningRequest {
    api_version: String,
    key: RequestKey,
    signature_algorithm: String,
    message: RequestMessage,
    context: RequestContext,
}

#[derive(Debug, Deserialize)]
struct RequestKey {
    id: String,
    fingerprint: String,
}

#[derive(Debug, Deserialize)]
struct RequestMessage {
    #[serde(rename = "type")]
    message_type: String,
    encoding: String,
    value: String,
}

/// Release context supplied by the caller.
///
/// Repository/ref/commit fields are useful to both Actions and a future local
/// GitHub identity flow. Workflow-run fields are optional in the wire model so
/// that local identities do not need fake Actions metadata; the current Actions
/// verifier still requires exact values for all of them.
#[derive(Debug, Clone, Deserialize)]
struct RequestContext {
    board: String,
    version: String,
    repository: String,
    repository_id: String,
    #[serde(rename = "ref")]
    git_ref: String,
    ref_type: String,
    commit_sha: String,
    #[serde(default)]
    event_name: Option<String>,
    #[serde(default)]
    workflow_ref: Option<String>,
    #[serde(default)]
    run_id: Option<String>,
    #[serde(default)]
    run_attempt: Option<String>,
}

struct ValidatedSigningRequest {
    digest: [u8; 32],
    context: RequestContext,
}

#[derive(Serialize)]
pub struct SignatureResponse {
    api_version: &'static str,
    request_id: String,
    key: SignatureResponseKey,
    signature_algorithm: &'static str,
    signature: SignatureValue,
}

#[derive(Serialize)]
struct SignatureResponseKey {
    id: String,
    fingerprint: String,
}

#[derive(Serialize)]
struct SignatureValue {
    encoding: &'static str,
    value: String,
}

pub async fn create_signature(
    State(state): State<AppState>,
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
                    reason: api_error.title.to_owned(),
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
                "The request body is not a valid signing-service JSON object.",
                &attempt_request_id,
            );
            audit_best_effort(
                &state,
                audit_record(
                    &attempt_request_id,
                    "sign",
                    false,
                    error.title,
                    Some(&principal),
                    AuditDetails::default(),
                ),
            )
            .await;
            return Err(error);
        }
    };

    let request_key_id = request.key.id.clone();
    let request_fingerprint = request.key.fingerprint.clone();
    let validated = match validate_signing_request(&state, &principal, request) {
        Ok(validated) => validated,
        Err(mut error) => {
            error.request_id = attempt_request_id.clone();
            audit_best_effort(
                &state,
                audit_record(
                    &attempt_request_id,
                    "sign",
                    false,
                    error.title,
                    Some(&principal),
                    AuditDetails {
                        key_id: Some(&request_key_id),
                        fingerprint: Some(&request_fingerprint),
                        ..AuditDetails::default()
                    },
                ),
            )
            .await;
            return Err(error);
        }
    };

    // Validation above proved that the immutable key id exists and the
    // fingerprint/state are acceptable and the key is currently unlocked.
    let key = state
        .keys
        .get(&request_key_id)
        .expect("validated key must remain present in immutable keyring");
    let message_sha256 = hex::encode(Sha256::digest(validated.digest));
    let signature = key.sign_digest(&validated.digest).ok_or_else(|| {
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
                key_id: Some(&request_key_id),
                fingerprint: Some(&request_fingerprint),
                message_sha256: Some(&message_sha256),
                context: Some(&validated.context),
            },
        ),
    )
    .await;

    Ok(Json(SignatureResponse {
        api_version: API_VERSION,
        request_id: attempt_request_id,
        key: SignatureResponseKey {
            id: request_key_id,
            fingerprint: request_fingerprint,
        },
        signature_algorithm: SIGNATURE_ALGORITHM,
        signature: SignatureValue {
            encoding: "base64",
            value: BASE64.encode(signature),
        },
    }))
}

fn validate_signing_request(
    state: &AppState,
    principal: &AuthPrincipal,
    request: SigningRequest,
) -> Result<ValidatedSigningRequest, ApiError> {
    if request.api_version != API_VERSION {
        return Err(ApiError::unprocessable(
            "api-version-mismatch",
            "Unsupported API version",
            "The request api_version must be microtun-signing/v1.",
        ));
    }
    if !valid_key_id(&request.key.id) {
        return Err(unknown_key_error());
    }
    state
        .authz
        .authorize(principal, PolicyAction::Sign, &request.key.id)
        .map_err(|_| policy_denied_error())?;
    let Some(key) = state.keys.get(&request.key.id) else {
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
    let Some(fingerprint) = key.fingerprint() else {
        return Err(ApiError::without_request_id(
            StatusCode::LOCKED,
            "key-locked",
            "Signing key is locked",
            "The requested signing key must be manually unlocked before it can create signatures.",
        ));
    };
    if request.key.fingerprint != fingerprint {
        return Err(ApiError::without_request_id(
            StatusCode::CONFLICT,
            "key-fingerprint-mismatch",
            "Signing key fingerprint mismatch",
            "The requested key fingerprint does not match the immutable key identifier.",
        ));
    }
    if request.signature_algorithm != SIGNATURE_ALGORITHM {
        return Err(ApiError::unprocessable(
            "unsupported-signature-algorithm",
            "Unsupported signature algorithm",
            "signature_algorithm must be ed25519.",
        ));
    }
    if request.message.message_type != MESSAGE_TYPE || request.message.encoding != "base64" {
        return Err(ApiError::unprocessable(
            "unsupported-message-format",
            "Unsupported signing message",
            "The signer only accepts base64-encoded mcuboot-sha256 messages.",
        ));
    }

    let decoded = BASE64
        .decode(request.message.value.as_bytes())
        .map_err(|_| {
            ApiError::unprocessable(
                "invalid-message-base64",
                "Invalid signing message",
                "message.value is not valid base64.",
            )
        })?;
    let digest: [u8; 32] = decoded.try_into().map_err(|bytes: Vec<u8>| {
        ApiError::unprocessable(
            "invalid-message-length",
            "Invalid signing message length",
            if bytes.len() < 32 {
                "The decoded MCUboot SHA-256 signing vector is shorter than 32 bytes."
            } else {
                "The decoded MCUboot SHA-256 signing vector is longer than 32 bytes."
            },
        )
    })?;

    validate_release_version(&request.context.version)?;
    authorize_context(principal, &request.context)?;

    Ok(ValidatedSigningRequest {
        digest,
        context: request.context,
    })
}

fn unknown_key_error() -> ApiError {
    ApiError::without_request_id(
        StatusCode::NOT_FOUND,
        "unknown-key",
        "Unknown signing key",
        "The requested immutable signing key identifier does not exist.",
    )
}

fn validate_release_version(version: &str) -> Result<(), ApiError> {
    let parsed = Version::parse(version).map_err(|_| {
        ApiError::unprocessable(
            "invalid-release-version",
            "Invalid release version",
            "context.version must be release SemVer in canonical X.Y.Z form.",
        )
    })?;
    if !parsed.pre.is_empty()
        || !parsed.build.is_empty()
        || format!("{}.{}.{}", parsed.major, parsed.minor, parsed.patch) != version
    {
        return Err(ApiError::unprocessable(
            "invalid-release-version",
            "Invalid release version",
            "context.version must be release SemVer in canonical X.Y.Z form.",
        ));
    }
    Ok(())
}

fn authorize_context(principal: &AuthPrincipal, context: &RequestContext) -> Result<(), ApiError> {
    match &principal.source {
        AuthSource::GithubAccount(_) => authorize_release_tag_context(context),
        AuthSource::GithubActions(actions) => authorize_actions_context(actions, context),
    }
}

fn authorize_actions_context(
    actions: &crate::auth::GithubActionsIdentity,
    context: &RequestContext,
) -> Result<(), ApiError> {
    if context.repository != actions.repository || context.repository_id != actions.repository_id {
        return Err(ApiError::without_request_id(
            StatusCode::FORBIDDEN,
            "github-context-mismatch",
            "Release context does not match authenticated GitHub identity",
            "The request repository does not match the authenticated GitHub Actions identity.",
        ));
    }

    let workflow_matches = context.event_name.as_deref() == Some(actions.event_name.as_str())
        && context.workflow_ref.as_deref() == Some(actions.workflow_ref.as_str())
        && context.run_id.as_deref() == Some(actions.run_id.as_str())
        && context.run_attempt.as_deref() == Some(actions.run_attempt.as_str());
    let git_matches = context.git_ref == actions.git_ref
        && context.ref_type == actions.ref_type
        && context.commit_sha.eq_ignore_ascii_case(&actions.sha);

    if !workflow_matches || !git_matches {
        return Err(ApiError::without_request_id(
            StatusCode::FORBIDDEN,
            "github-actions-context-mismatch",
            "Release context does not match authenticated GitHub Actions identity",
            "The request Git/ref/workflow context differs from the authenticated GitHub Actions OIDC identity.",
        ));
    }

    authorize_release_tag_context(context)
}

fn authorize_release_tag_context(context: &RequestContext) -> Result<(), ApiError> {
    if context.ref_type != "tag" {
        return Err(ApiError::without_request_id(
            StatusCode::FORBIDDEN,
            "tag-required",
            "A release tag is required",
            "Firmware signing requires a tag release context.",
        ));
    }
    let tag = context.git_ref.strip_prefix("refs/tags/").ok_or_else(|| {
        ApiError::without_request_id(
            StatusCode::FORBIDDEN,
            "tag-required",
            "A release tag is required",
            "context.ref must be a refs/tags/* reference.",
        )
    })?;
    let tag_version = tag.strip_prefix('v').unwrap_or(tag);
    if tag_version != context.version {
        return Err(ApiError::without_request_id(
            StatusCode::FORBIDDEN,
            "tag-version-mismatch",
            "Release version does not match tag",
            "context.version must exactly match the release tag (with an optional leading v on the tag).",
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
        OAuthFlowError::InvalidState => ApiError::new(
            StatusCode::BAD_REQUEST,
            "oauth-state-invalid",
            "GitHub OAuth state is invalid or expired",
            "Restart the GitHub login flow and try again.",
            request_id,
        ),
        OAuthFlowError::AuthorizationDenied => ApiError::new(
            StatusCode::UNAUTHORIZED,
            "oauth-authorization-denied",
            "GitHub authorization was not completed",
            "GitHub did not return a usable authorization code.",
            request_id,
        ),
        OAuthFlowError::ExchangeFailed => ApiError::new(
            StatusCode::BAD_GATEWAY,
            "oauth-code-exchange-failed",
            "GitHub OAuth code exchange failed",
            "The signer could not exchange the GitHub authorization code.",
            request_id,
        ),
        OAuthFlowError::IdentityProviderUnavailable => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "identity-provider-unavailable",
            "GitHub identity verification is temporarily unavailable",
            "The signer could not complete GitHub OAuth authentication.",
            request_id,
        ),
        OAuthFlowError::ClaimsDenied => ApiError::new(
            StatusCode::FORBIDDEN,
            "identity-not-authorized",
            "Authenticated identity is not authorized",
            "The authenticated GitHub account is not configured as a signer identity.",
            request_id,
        ),
        OAuthFlowError::SessionCapacity | OAuthFlowError::StateCapacity => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "oauth-capacity-exhausted",
            "GitHub OAuth login is temporarily unavailable",
            "The signer has reached its temporary OAuth session capacity.",
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
    fingerprint: Option<&'a str>,
    message_sha256: Option<&'a str>,
    context: Option<&'a RequestContext>,
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
        key_fingerprint: details.fingerprint.map(str::to_owned),
        message_sha256: details.message_sha256.map(str::to_owned),
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
        repository_id: actions.map(|identity| identity.repository_id.clone()),
        git_ref: actions.map(|identity| identity.git_ref.clone()),
        workflow_ref: actions.map(|identity| identity.workflow_ref.clone()),
        run_id: actions.map(|identity| identity.run_id.clone()),
        run_attempt: actions.map(|identity| identity.run_attempt.clone()),
        jti: principal.and_then(|principal| principal.jti.clone()),
        board: details.context.map(|context| context.board.clone()),
        version: details.context.map(|context| context.version.clone()),
    }
}

async fn audit_best_effort(_state: &AppState, record: AuditRecord) {
    tracing::info!(
        target: "microtun_firmware_signer::audit",
        request_id = %record.request_id,
        operation = %record.operation,
        success = record.success,
        reason = %record.reason,
        key_id = record.key_id.as_deref().unwrap_or(""),
        key_fingerprint = record.key_fingerprint.as_deref().unwrap_or(""),
        message_sha256 = record.message_sha256.as_deref().unwrap_or(""),
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
        repository_id = record.repository_id.as_deref().unwrap_or(""),
        git_ref = record.git_ref.as_deref().unwrap_or(""),
        workflow_ref = record.workflow_ref.as_deref().unwrap_or(""),
        run_id = record.run_id.as_deref().unwrap_or(""),
        run_attempt = record.run_attempt.as_deref().unwrap_or(""),
        jti = record.jti.as_deref().unwrap_or(""),
        board = record.board.as_deref().unwrap_or(""),
        version = record.version.as_deref().unwrap_or(""),
        "firmware signer audit event"
    );
}

#[derive(Debug, Serialize)]
struct ProblemBody {
    #[serde(rename = "type")]
    problem_type: String,
    title: String,
    status: u16,
    detail: String,
    request_id: String,
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    slug: &'static str,
    pub title: &'static str,
    detail: &'static str,
    request_id: String,
    authenticate: bool,
}

impl ApiError {
    fn new(
        status: StatusCode,
        slug: &'static str,
        title: &'static str,
        detail: &'static str,
        request_id: &str,
    ) -> Self {
        Self {
            status,
            slug,
            title,
            detail,
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
        let body = ProblemBody {
            problem_type: format!("urn:microtun:firmware-signing:{}", self.slug),
            title: self.title.to_owned(),
            status: self.status.as_u16(),
            detail: self.detail.to_owned(),
            request_id: self.request_id,
        };
        let mut response = (self.status, Json(body)).into_response();
        response.headers_mut().insert(
            CONTENT_TYPE,
            "application/problem+json"
                .parse()
                .expect("valid content type"),
        );
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
    fn only_canonical_release_semver_is_accepted() {
        assert!(validate_release_version("1.2.3").is_ok());
        assert!(validate_release_version("v1.2.3").is_err());
        assert!(validate_release_version("1.2.3-rc.1").is_err());
        assert!(validate_release_version("1.2.3+build").is_err());
    }

    fn release_context() -> RequestContext {
        RequestContext {
            board: "board".into(),
            version: "1.2.3".into(),
            repository: "owner/repo".into(),
            repository_id: "123".into(),
            git_ref: "refs/tags/v1.2.3".into(),
            ref_type: "tag".into(),
            commit_sha: "ABCDEF".into(),
            event_name: Some("push".into()),
            workflow_ref: Some("owner/repo/.github/workflows/release.yml@refs/tags/v1.2.3".into()),
            run_id: Some("42".into()),
            run_attempt: Some("1".into()),
        }
    }

    #[test]
    fn actions_context_still_requires_exact_workflow_metadata() {
        let principal = AuthPrincipal {
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
                git_ref: "refs/tags/v1.2.3".into(),
                ref_type: "tag".into(),
                sha: "abcdef".into(),
                workflow_ref: "owner/repo/.github/workflows/release.yml@refs/tags/v1.2.3".into(),
                event_name: "push".into(),
                run_id: "42".into(),
                run_attempt: "1".into(),
            })),
        };
        let mut context = release_context();

        assert!(authorize_context(&principal, &context).is_ok());
        context.workflow_ref = None;
        assert!(authorize_context(&principal, &context).is_err());
    }

    #[test]
    fn account_context_requires_a_release_tag_but_not_actions_metadata() {
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
        let mut context = release_context();
        context.event_name = None;
        context.workflow_ref = None;
        context.run_id = None;
        context.run_attempt = None;

        assert!(authorize_context(&principal, &context).is_ok());
        context.git_ref = "refs/heads/main".into();
        context.ref_type = "branch".into();
        assert!(authorize_context(&principal, &context).is_err());
    }
}
