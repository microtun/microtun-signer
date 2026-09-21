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
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::{
    auth::{AuthError, AuthPrincipal, AuthSource, Authenticator, OAuthFlowError},
    authorization::Authorizer,
    config::{KeyState, PolicyAction, valid_key_id},
    key::{KeyRing, UnlockError, UnlockOutcome},
};
use zeroize::Zeroizing;

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

#[derive(Debug, Deserialize)]
pub struct GithubOAuthCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(Serialize)]
struct OAuthSessionResponse {
    access_token: String,
    expires_in: u64,
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
        access_token: grant.access_token,
        expires_in: grant.expires_in,
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
    State(state): State<UnlockState>,
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

    tracing::info!(
        target: "microtun_firmware_signer::audit",
        request_id = %request_id,
        operation = "unlock-key",
        success = true,
        reason = if outcome == UnlockOutcome::AlreadyUnlocked { "already-unlocked" } else { "ok" },
        key_id = key.id(),
        "firmware signer unlock audit event"
    );

    Ok(StatusCode::NO_CONTENT)
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
        target: "microtun_firmware_signer::audit",
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
        commit_sha = record.commit_sha.as_deref().unwrap_or(""),
        event_name = record.event_name.as_deref().unwrap_or(""),
        workflow_ref = record.workflow_ref.as_deref().unwrap_or(""),
        run_id = record.run_id.as_deref().unwrap_or(""),
        run_attempt = record.run_attempt.as_deref().unwrap_or(""),
        jti = record.jti.as_deref().unwrap_or(""),
        "firmware signer audit event"
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
                sha: "abcdef".into(),
                workflow_ref: "owner/repo/.github/workflows/release.yml@refs/tags/v1.2.3".into(),
                event_name: "push".into(),
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
}
