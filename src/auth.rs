use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::http::{HeaderMap, header::AUTHORIZATION};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::{Mutex as AsyncMutex, RwLock};
use zeroize::Zeroizing;

use crate::{
    config::{GithubActionsConfig, GithubConfig, IdentityConfig, IdentityKind},
    key::load_systemd_credential,
};

const GITHUB_ACTIONS_ISSUER: &str = "https://token.actions.githubusercontent.com";
const GITHUB_ACCOUNT_ISSUER: &str = "https://github.com";
const MAX_BEARER_TOKEN_BYTES: usize = 16 * 1024;
const MAX_OAUTH_SESSIONS: usize = 4096;

/// Upper bound on remembered GitHub Actions `jti` values. Entries are only
/// recorded for tokens that already resolved to a configured identity, so
/// this is not reachable by arbitrary GitHub users minting tokens for our
/// audience in their own repositories.
const MAX_SEEN_JTIS: usize = 65_536;
const MAX_JTI_BYTES: usize = 256;
const JWT_LEEWAY_SECONDS: u64 = 60;

/// An unknown `kid` may trigger at most one JWKS fetch per interval. This
/// stops unauthenticated callers from turning the signer into a request
/// amplifier against GitHub (and getting it rate-limited).
const JWKS_MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
/// If GitHub's JWKS endpoint is unavailable, previously fetched keys remain
/// usable for this long after their last successful fetch.
const JWKS_MAX_STALENESS: Duration = Duration::from_secs(24 * 60 * 60);
const JWKS_MAX_BYTES: usize = 256 * 1024;

/// `read:user` makes GitHub include `two_factor_authentication` in the
/// `GET /user` response. The GitHub token is revoked immediately after use.
const OAUTH_SCOPE: &str = "read:user";
const SESSION_TOKEN_PREFIX: &str = "mts_";
const MAX_USED_DEVICE_TOKENS: usize = 65_536;
const DEVICE_TOKEN_REPLAY_TTL: Duration = Duration::from_secs(60 * 60);

#[derive(Clone)]
pub struct Authenticator {
    inner: Arc<Inner>,
}

struct Inner {
    github: GithubConfig,
    github_oauth_client_secret: Zeroizing<String>,
    actions: GithubActionsConfig,
    identities: Vec<IdentityConfig>,
    http: reqwest::Client,
    jwks: RwLock<JwksCache>,
    /// Serialises JWKS refreshes so concurrent cache misses cause one fetch.
    jwks_refresh: AsyncMutex<()>,
    /// Device-flow bootstrap tokens are single-use within this process.
    device_token_replay: Mutex<DeviceTokenReplay>,
    /// Keyed by SHA-256 of the bearer token; raw session tokens are never stored.
    oauth_sessions: RwLock<HashMap<[u8; 32], GithubAccountSession>>,
    seen_jtis: Mutex<HashMap<String, Instant>>,
}

#[derive(Default)]
struct JwksCache {
    fetched_at: Option<Instant>,
    last_attempt: Option<Instant>,
    keys: HashMap<String, RsaJwk>,
}

#[derive(Default)]
struct DeviceTokenReplay {
    in_flight: HashSet<[u8; 32]>,
    used: HashMap<[u8; 32], Instant>,
}

struct DeviceTokenUseGuard {
    inner: Arc<Inner>,
    key: [u8; 32],
}

impl DeviceTokenUseGuard {
    fn mark_consumed(&self) -> Result<(), OAuthFlowError> {
        let now = Instant::now();
        let mut replay = self
            .inner
            .device_token_replay
            .lock()
            .map_err(|_| OAuthFlowError::ReplayCacheUnavailable)?;
        replay.used.retain(|_, expires_at| *expires_at > now);
        if replay.used.len() >= MAX_USED_DEVICE_TOKENS && !replay.used.contains_key(&self.key) {
            return Err(OAuthFlowError::ReplayCacheUnavailable);
        }
        replay.used.insert(self.key, now + DEVICE_TOKEN_REPLAY_TTL);
        Ok(())
    }
}

impl Drop for DeviceTokenUseGuard {
    fn drop(&mut self) {
        if let Ok(mut replay) = self.inner.device_token_replay.lock() {
            replay.in_flight.remove(&self.key);
        }
    }
}

#[derive(Clone, Debug)]
struct GithubAccountSession {
    expires_at: Instant,
    identity_id: String,
    user_id: String,
    login: String,
}

#[derive(Clone, Debug, Deserialize)]
struct JwksDocument {
    keys: Vec<RsaJwk>,
}

#[derive(Clone, Debug, Deserialize)]
struct RsaJwk {
    kty: String,
    kid: String,
    alg: Option<String>,
    n: String,
    e: String,
    #[serde(rename = "use")]
    use_: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct GithubActionsClaims {
    pub iss: String,
    pub aud: Audience,
    pub sub: String,
    pub exp: u64,
    pub jti: Option<String>,
    pub actor: Option<String>,
    pub actor_id: Option<String>,
    pub repository: String,
    pub repository_id: String,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub ref_type: String,
    /// GitHub has emitted this both as a JSON boolean and as "true"/"false".
    pub ref_protected: Option<serde_json::Value>,
    pub sha: String,
    pub workflow_ref: String,
    pub workflow_sha: Option<String>,
    pub event_name: String,
    pub run_id: String,
    pub run_attempt: String,
    pub environment: Option<String>,
    pub runner_environment: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    pub fn as_audit_string(&self) -> String {
        match self {
            Self::One(value) => value.clone(),
            Self::Many(values) => values.join(","),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct GithubUserResponse {
    login: String,
    id: u64,
    /// Only present in the private user response (requires `read:user`).
    two_factor_authentication: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct GithubTokenCheckResponse {
    scopes: Vec<String>,
    app: GithubTokenCheckApp,
}

#[derive(Debug, Deserialize)]
struct GithubTokenCheckApp {
    client_id: String,
}

#[derive(Serialize)]
struct GithubTokenCheckRequest<'a> {
    access_token: &'a str,
}

#[derive(Serialize)]
struct GithubTokenRevocationRequest<'a> {
    access_token: &'a str,
}

#[derive(Clone, Debug)]
pub struct GithubAccountIdentity {
    pub user_id: String,
    pub login: String,
}

#[derive(Clone, Debug)]
pub struct GithubActionsIdentity {
    pub repository: String,
    pub repository_id: String,
    pub actor: Option<String>,
    pub actor_id: Option<String>,
    pub git_ref: String,
    pub ref_type: String,
    pub ref_protected: bool,
    pub sha: String,
    pub workflow_ref: String,
    pub event_name: String,
    pub environment: Option<String>,
    pub run_id: String,
    pub run_attempt: String,
}

#[derive(Clone, Debug)]
pub enum AuthSource {
    GithubAccount(GithubAccountIdentity),
    GithubActions(Box<GithubActionsIdentity>),
}

#[derive(Clone, Debug)]
pub struct AuthPrincipal {
    /// Local, administrator-chosen identity name referenced by policies.
    pub identity_id: String,
    /// Stable external principal key suitable for audit correlation.
    pub principal_key: String,
    pub auth_method: &'static str,
    pub issuer: String,
    pub audience: Option<String>,
    pub subject: String,
    pub jti: Option<String>,
    pub source: AuthSource,
}

#[derive(Clone, Debug)]
pub struct OAuthDeviceConfig {
    pub client_id: String,
    pub device_code_url: String,
    pub access_token_url: String,
    pub scope: &'static str,
}

#[derive(Clone, Debug)]
pub struct OAuthSessionGrant {
    pub access_token: String,
    pub expires_in: u64,
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("authorization bearer token is missing or malformed")]
    MissingBearer,
    #[error("bearer token is too large")]
    TokenTooLarge,
    #[error("bearer token is invalid or expired")]
    InvalidToken,
    #[error("GitHub Actions OIDC token has already been used")]
    TokenReplayed,
    #[error("GitHub Actions OIDC replay cache is unavailable")]
    ReplayCacheUnavailable,
    #[error("GitHub Actions OIDC key discovery failed")]
    KeyDiscovery,
    #[error("GitHub identity provider is temporarily unavailable")]
    IdentityProviderUnavailable,
    #[error("authenticated GitHub subject does not match a configured identity")]
    ClaimsDenied,
}

#[derive(Debug, Error)]
pub enum OAuthFlowError {
    #[error("GitHub OAuth token is invalid or was not issued to this signer application")]
    TokenValidationFailed,
    #[error("GitHub OAuth bootstrap token has already been used")]
    TokenReplayed,
    #[error("GitHub OAuth replay cache is unavailable")]
    ReplayCacheUnavailable,
    #[error("GitHub OAuth token was not granted the required scope")]
    ScopeNotGranted,
    #[error("GitHub identity provider is temporarily unavailable")]
    IdentityProviderUnavailable,
    #[error("GitHub OAuth token could not be revoked")]
    TokenRevocationFailed,
    #[error("authenticated GitHub account does not match a configured identity")]
    ClaimsDenied,
    #[error("authenticated GitHub account does not have two-factor authentication enabled")]
    TwoFactorRequired,
    #[error("too many OAuth sessions are active")]
    SessionCapacity,
}

impl Authenticator {
    pub fn new(
        github: GithubConfig,
        actions: GithubActionsConfig,
        identities: Vec<IdentityConfig>,
    ) -> anyhow::Result<Self> {
        let github_oauth_client_secret = load_systemd_credential(
            &github.oauth_client_secret_credential,
            "GitHub OAuth client secret",
        )?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!(
                "microtun-signer/",
                env!("CARGO_PKG_VERSION")
            ))
            .build()?;
        Ok(Self {
            inner: Arc::new(Inner {
                github,
                github_oauth_client_secret,
                actions,
                identities,
                http,
                jwks: RwLock::new(JwksCache::default()),
                jwks_refresh: AsyncMutex::new(()),
                device_token_replay: Mutex::new(DeviceTokenReplay::default()),
                oauth_sessions: RwLock::new(HashMap::new()),
                seen_jtis: Mutex::new(HashMap::new()),
            }),
        })
    }

    /// Public parameters needed by a CLI to run GitHub's OAuth device flow.
    /// The client ID and endpoint URLs are not secrets; the client secret stays
    /// server-side and is used later to verify that the returned token belongs
    /// to this OAuth application.
    pub fn github_oauth_device_config(&self) -> OAuthDeviceConfig {
        OAuthDeviceConfig {
            client_id: self.inner.github.oauth_client_id.clone(),
            device_code_url: self.inner.github.oauth_device_code_url.clone(),
            access_token_url: self.inner.github.oauth_access_token_url.clone(),
            scope: OAUTH_SCOPE,
        }
    }

    /// Exchange a GitHub device-flow user token for the signer's own short-lived
    /// session. The token must be single-use, belong to this exact OAuth App,
    /// resolve to an authorized 2FA-enabled account, and be revoked at GitHub
    /// before any signer-local session is minted.
    pub async fn complete_github_device_oauth(
        &self,
        access_token: &str,
    ) -> Result<OAuthSessionGrant, OAuthFlowError> {
        if access_token.is_empty() || access_token.len() > MAX_BEARER_TOKEN_BYTES {
            return Err(OAuthFlowError::TokenValidationFailed);
        }

        let use_guard = self.begin_device_token_use(access_token)?;
        let granted_scopes = self.check_github_oauth_token(access_token).await?;

        let outcome = self
            .github_account_from_token(access_token, &granted_scopes)
            .await;

        // Revocation is fail-closed. Even a valid configured account receives
        // no signer session unless the GitHub bootstrap credential is gone. A
        // revocation failure deliberately leaves the token retryable so a
        // later request can try to revoke it again.
        self.revoke_github_token(access_token).await?;

        // Only a token proven to belong to this OAuth App and successfully
        // revoked at GitHub enters the retained replay cache. In-flight replay
        // protection covers the entire exchange before this point.
        use_guard.mark_consumed()?;
        let (identity_id, user) = outcome?;
        self.mint_github_account_session(identity_id, user).await
    }

    fn begin_device_token_use(
        &self,
        access_token: &str,
    ) -> Result<DeviceTokenUseGuard, OAuthFlowError> {
        let key = session_key(access_token);
        let now = Instant::now();
        let mut replay = self
            .inner
            .device_token_replay
            .lock()
            .map_err(|_| OAuthFlowError::ReplayCacheUnavailable)?;
        replay.used.retain(|_, expires_at| *expires_at > now);
        if replay.used.contains_key(&key) || !replay.in_flight.insert(key) {
            return Err(OAuthFlowError::TokenReplayed);
        }
        drop(replay);
        Ok(DeviceTokenUseGuard {
            inner: self.inner.clone(),
            key,
        })
    }

    async fn mint_github_account_session(
        &self,
        identity_id: String,
        user: GithubUserResponse,
    ) -> Result<OAuthSessionGrant, OAuthFlowError> {
        let now = Instant::now();
        let expires_in = self.inner.github.oauth_session_ttl_seconds;
        let session = GithubAccountSession {
            expires_at: now + Duration::from_secs(expires_in),
            identity_id,
            user_id: user.id.to_string(),
            login: user.login,
        };
        let token = format!(
            "{SESSION_TOKEN_PREFIX}{}",
            B64URL.encode(random_bytes::<32>())
        );

        let mut sessions = self.inner.oauth_sessions.write().await;
        sessions.retain(|_, session| session.expires_at > now);
        if sessions.len() >= MAX_OAUTH_SESSIONS {
            return Err(OAuthFlowError::SessionCapacity);
        }
        sessions.insert(session_key(&token), session);

        Ok(OAuthSessionGrant {
            access_token: token,
            expires_in,
        })
    }

    pub async fn authenticate(&self, headers: &HeaderMap) -> Result<AuthPrincipal, AuthError> {
        let token = bearer_token(headers)?;

        // GitHub Actions OIDC tokens are JWTs. All other accepted credentials
        // must be signer-local sessions minted by our own GitHub OAuth flow;
        // arbitrary GitHub OAuth/App bearer tokens are deliberately rejected.
        if is_github_actions_jwt(token) {
            self.authenticate_github_actions(token).await
        } else {
            self.authenticate_github_account_session(token).await
        }
    }

    async fn authenticate_github_account_session(
        &self,
        token: &str,
    ) -> Result<AuthPrincipal, AuthError> {
        if !token.starts_with(SESSION_TOKEN_PREFIX) {
            return Err(AuthError::InvalidToken);
        }

        let now = Instant::now();
        let session = {
            let sessions = self.inner.oauth_sessions.read().await;
            sessions
                .get(&session_key(token))
                .filter(|session| session.expires_at > now)
                .cloned()
                .ok_or(AuthError::InvalidToken)?
        };

        Ok(AuthPrincipal {
            identity_id: session.identity_id,
            principal_key: format!("github-account:{}", session.user_id),
            auth_method: "github-oauth-session",
            issuer: GITHUB_ACCOUNT_ISSUER.to_owned(),
            audience: Some(self.inner.github.oauth_client_id.clone()),
            subject: session.user_id.clone(),
            jti: None,
            source: AuthSource::GithubAccount(GithubAccountIdentity {
                user_id: session.user_id,
                login: session.login,
            }),
        })
    }

    /// Resolve a verified GitHub OAuth token to a configured identity whose
    /// account has two-factor authentication enabled.
    async fn github_account_from_token(
        &self,
        token: &str,
        granted_scopes: &[String],
    ) -> Result<(String, GithubUserResponse), OAuthFlowError> {
        if !scope_grants_read_user(granted_scopes) {
            return Err(OAuthFlowError::ScopeNotGranted);
        }

        let user = self
            .resolve_github_user(token)
            .await
            .map_err(|error| match error {
                AuthError::ClaimsDenied => OAuthFlowError::ClaimsDenied,
                AuthError::InvalidToken => OAuthFlowError::TokenValidationFailed,
                _ => OAuthFlowError::IdentityProviderUnavailable,
            })?;
        let user_id = user.id.to_string();
        let identity = self
            .inner
            .identities
            .iter()
            .find(|identity| matches_github_account_identity(identity, &user_id, &user.login))
            .ok_or(OAuthFlowError::ClaimsDenied)?;

        // Fail closed: a missing field means GitHub returned the public
        // profile only, so 2FA status is unknown.
        if user.two_factor_authentication != Some(true) {
            return Err(OAuthFlowError::TwoFactorRequired);
        }
        Ok((identity.id.clone(), user))
    }

    async fn check_github_oauth_token(&self, token: &str) -> Result<Vec<String>, OAuthFlowError> {
        let github = &self.inner.github;
        let response = self
            .inner
            .http
            .post(format!(
                "{}/applications/{}/token",
                github.api_url, github.oauth_client_id
            ))
            .basic_auth(
                &github.oauth_client_id,
                Some(self.inner.github_oauth_client_secret.as_str()),
            )
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", &github.api_version)
            .json(&GithubTokenCheckRequest {
                access_token: token,
            })
            .send()
            .await
            .map_err(|_| OAuthFlowError::IdentityProviderUnavailable)?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(OAuthFlowError::TokenValidationFailed);
        }
        if !response.status().is_success() {
            return Err(OAuthFlowError::IdentityProviderUnavailable);
        }

        let checked = response
            .json::<GithubTokenCheckResponse>()
            .await
            .map_err(|_| OAuthFlowError::IdentityProviderUnavailable)?;
        if checked.app.client_id != github.oauth_client_id {
            return Err(OAuthFlowError::TokenValidationFailed);
        }
        Ok(checked.scopes)
    }

    async fn resolve_github_user(&self, token: &str) -> Result<GithubUserResponse, AuthError> {
        let response = self
            .inner
            .http
            .get(format!("{}/user", self.inner.github.api_url))
            .bearer_auth(token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", &self.inner.github.api_version)
            .send()
            .await
            .map_err(|_| AuthError::IdentityProviderUnavailable)?;

        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(AuthError::InvalidToken);
        }
        if !response.status().is_success() {
            return Err(AuthError::IdentityProviderUnavailable);
        }
        response
            .json::<GithubUserResponse>()
            .await
            .map_err(|_| AuthError::IdentityProviderUnavailable)
    }

    /// Revoke a GitHub OAuth bootstrap token before minting a signer session.
    /// A 404 is also safe: GitHub is confirming that this app no longer has
    /// that token. Any other failure is fail-closed.
    async fn revoke_github_token(&self, token: &str) -> Result<(), OAuthFlowError> {
        let github = &self.inner.github;
        let response = self
            .inner
            .http
            .delete(format!(
                "{}/applications/{}/token",
                github.api_url, github.oauth_client_id
            ))
            .basic_auth(
                &github.oauth_client_id,
                Some(self.inner.github_oauth_client_secret.as_str()),
            )
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", &github.api_version)
            .json(&GithubTokenRevocationRequest {
                access_token: token,
            })
            .send()
            .await
            .map_err(|_| OAuthFlowError::TokenRevocationFailed)?;

        if matches!(
            response.status(),
            reqwest::StatusCode::NO_CONTENT | reqwest::StatusCode::NOT_FOUND
        ) {
            Ok(())
        } else {
            Err(OAuthFlowError::TokenRevocationFailed)
        }
    }

    async fn authenticate_github_actions(&self, token: &str) -> Result<AuthPrincipal, AuthError> {
        let actions = &self.inner.actions;
        let header = decode_header(token).map_err(|_| AuthError::InvalidToken)?;
        if header.alg != Algorithm::RS256 {
            return Err(AuthError::InvalidToken);
        }
        let kid = header.kid.as_deref().ok_or(AuthError::InvalidToken)?;
        let jwk = self.jwk_for(kid).await?;
        let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
            .map_err(|_| AuthError::KeyDiscovery)?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.leeway = JWT_LEEWAY_SECONDS;
        validation.validate_nbf = true;
        validation.set_audience(&[actions.audience.as_str()]);
        validation.set_issuer(&[GITHUB_ACTIONS_ISSUER]);
        // jsonwebtoken only understands exp/nbf/iss/aud/sub here; `jti` is
        // required explicitly below.
        validation.set_required_spec_claims(&["exp", "nbf", "iss", "aud", "sub"]);

        let data = decode::<GithubActionsClaims>(token, &decoding_key, &validation)
            .map_err(|_| AuthError::InvalidToken)?;
        let claims = data.claims;
        let jti = claims
            .jti
            .clone()
            .filter(|jti| !jti.is_empty() && jti.len() <= MAX_JTI_BYTES)
            .ok_or(AuthError::InvalidToken)?;
        let identity = resolve_github_actions_identity(&self.inner.identities, &claims)?;

        // One-time use: record only after the token resolved to a configured
        // identity, so foreign tokens cannot fill the replay cache.
        self.record_jti(&jti, claims.exp)?;

        let ref_protected = claim_is_true(claims.ref_protected.as_ref());
        Ok(AuthPrincipal {
            identity_id: identity.id.clone(),
            principal_key: format!("github-actions:repository:{}", claims.repository_id),
            auth_method: "github-actions-oidc",
            issuer: claims.iss.clone(),
            audience: Some(claims.aud.as_audit_string()),
            subject: claims.sub.clone(),
            jti: Some(jti),
            source: AuthSource::GithubActions(Box::new(GithubActionsIdentity {
                repository: claims.repository,
                repository_id: claims.repository_id,
                actor: claims.actor,
                actor_id: claims.actor_id,
                git_ref: claims.git_ref,
                ref_type: claims.ref_type,
                ref_protected,
                sha: claims.sha,
                workflow_ref: claims.workflow_ref,
                event_name: claims.event_name,
                environment: claims.environment,
                run_id: claims.run_id,
                run_attempt: claims.run_attempt,
            })),
        })
    }

    fn record_jti(&self, jti: &str, exp: u64) -> Result<(), AuthError> {
        let now = Instant::now();
        let remaining = exp
            .saturating_sub(unix_now())
            .saturating_add(JWT_LEEWAY_SECONDS);
        let mut seen = self
            .inner
            .seen_jtis
            .lock()
            .map_err(|_| AuthError::ReplayCacheUnavailable)?;
        seen.retain(|_, until| *until > now);
        if seen.contains_key(jti) {
            return Err(AuthError::TokenReplayed);
        }
        if seen.len() >= MAX_SEEN_JTIS {
            return Err(AuthError::ReplayCacheUnavailable);
        }
        seen.insert(jti.to_owned(), now + Duration::from_secs(remaining));
        Ok(())
    }

    async fn cached_jwk(&self, kid: &str, ttl: Duration) -> Option<RsaJwk> {
        let cache = self.inner.jwks.read().await;
        let fresh = cache.fetched_at.is_some_and(|at| at.elapsed() < ttl);
        if fresh {
            cache.keys.get(kid).cloned()
        } else {
            None
        }
    }

    async fn jwk_for(&self, kid: &str) -> Result<RsaJwk, AuthError> {
        let ttl = Duration::from_secs(self.inner.actions.jwks_ttl_seconds);
        if let Some(key) = self.cached_jwk(kid, ttl).await {
            return Ok(key);
        }

        // Single-flight: one task refreshes, the rest wait and re-check.
        let _refresh = self.inner.jwks_refresh.lock().await;
        if let Some(key) = self.cached_jwk(kid, ttl).await {
            return Ok(key);
        }

        let may_fetch = {
            let mut cache = self.inner.jwks.write().await;
            let allowed = cache
                .last_attempt
                .is_none_or(|at| at.elapsed() >= JWKS_MIN_REFRESH_INTERVAL);
            if allowed {
                cache.last_attempt = Some(Instant::now());
            }
            allowed
        };
        if may_fetch {
            match self.fetch_jwks().await {
                Ok(keys) => {
                    let mut cache = self.inner.jwks.write().await;
                    cache.keys = keys;
                    cache.fetched_at = Some(Instant::now());
                }
                Err(error) => {
                    tracing::warn!(error = %error, "GitHub Actions JWKS refresh failed");
                }
            }
        }

        let cache = self.inner.jwks.read().await;
        let usable = cache
            .fetched_at
            .is_some_and(|at| at.elapsed() < ttl.saturating_add(JWKS_MAX_STALENESS));
        if !usable {
            return Err(AuthError::KeyDiscovery);
        }
        // An unknown kid against a usable key set is a bad token, not an
        // outage: answer 401 without another fetch until the interval passes.
        cache.keys.get(kid).cloned().ok_or(AuthError::InvalidToken)
    }

    async fn fetch_jwks(&self) -> Result<HashMap<String, RsaJwk>, AuthError> {
        let mut response = self
            .inner
            .http
            .get(&self.inner.actions.jwks_url)
            .send()
            .await
            .map_err(|_| AuthError::KeyDiscovery)?
            .error_for_status()
            .map_err(|_| AuthError::KeyDiscovery)?;

        if response
            .content_length()
            .is_some_and(|length| length > JWKS_MAX_BYTES as u64)
        {
            return Err(AuthError::KeyDiscovery);
        }
        // Enforce the size limit while streaming, so chunked responses
        // without Content-Length are bounded too.
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| AuthError::KeyDiscovery)?
        {
            if body.len() + chunk.len() > JWKS_MAX_BYTES {
                return Err(AuthError::KeyDiscovery);
            }
            body.extend_from_slice(&chunk);
        }
        let document: JwksDocument =
            serde_json::from_slice(&body).map_err(|_| AuthError::KeyDiscovery)?;

        let mut keys = HashMap::new();
        for key in document.keys {
            let algorithm_ok = key.alg.as_deref().is_none_or(|alg| alg == "RS256");
            let use_ok = key.use_.as_deref().is_none_or(|use_| use_ == "sig");
            if key.kty == "RSA" && algorithm_ok && use_ok && !key.kid.is_empty() {
                keys.insert(key.kid.clone(), key);
            }
        }
        if keys.is_empty() {
            return Err(AuthError::KeyDiscovery);
        }
        Ok(keys)
    }
}

#[cfg(test)]
impl Authenticator {
    pub(crate) fn for_tests() -> Self {
        Self::for_tests_with_github("https://api.github.com", Vec::new())
    }

    fn for_tests_with_github(api_url: &str, identities: Vec<IdentityConfig>) -> Self {
        let github: GithubConfig = toml::from_str(&format!(
            r#"APIURL = "{api_url}"
OAuthClientID = "Iv1.test"
"#
        ))
        .expect("test GitHub config");
        let actions: GithubActionsConfig = toml::from_str("").expect("test Actions config");
        Self {
            inner: Arc::new(Inner {
                github,
                github_oauth_client_secret: Zeroizing::new("secret".into()),
                actions,
                identities,
                http: reqwest::Client::new(),
                jwks: RwLock::new(JwksCache::default()),
                jwks_refresh: AsyncMutex::new(()),
                device_token_replay: Mutex::new(DeviceTokenReplay::default()),
                oauth_sessions: RwLock::new(HashMap::new()),
                seen_jtis: Mutex::new(HashMap::new()),
            }),
        }
    }
}

/// Fill a fixed-size buffer from the operating system CSPRNG.
fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes).expect("operating system random number generator failed");
    bytes
}

fn session_key(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

fn claim_is_true(value: Option<&serde_json::Value>) -> bool {
    match value {
        Some(serde_json::Value::Bool(flag)) => *flag,
        Some(serde_json::Value::String(text)) => text == "true",
        _ => false,
    }
}

/// GitHub reports granted OAuth scopes on token inspection. `user` implies
/// `read:user`.
fn scope_grants_read_user(scopes: &[String]) -> bool {
    scopes
        .iter()
        .any(|scope| scope == OAUTH_SCOPE || scope == "user")
}

fn is_github_actions_jwt(token: &str) -> bool {
    if token.split('.').count() != 3 {
        return false;
    }
    decode_header(token).is_ok_and(|header| header.alg == Algorithm::RS256 && header.kid.is_some())
}

fn matches_github_account_identity(identity: &IdentityConfig, user_id: &str, login: &str) -> bool {
    identity.kind == IdentityKind::GithubAccount
        && identity.github_user_id.as_deref() == Some(user_id)
        && identity
            .github_login
            .as_ref()
            .is_none_or(|expected| expected.eq_ignore_ascii_case(login))
}

fn resolve_github_actions_identity<'a>(
    identities: &'a [IdentityConfig],
    claims: &GithubActionsClaims,
) -> Result<&'a IdentityConfig, AuthError> {
    let mut matches = identities
        .iter()
        .filter(|identity| matches_github_actions_identity(identity, claims));
    let identity = matches.next().ok_or(AuthError::ClaimsDenied)?;

    // Multiple identities may intentionally share a RepositoryID (for
    // example release and nightly workflows). Never select one by config
    // order if their constraints overlap: ambiguous authentication is denied.
    if matches.next().is_some() {
        return Err(AuthError::ClaimsDenied);
    }
    Ok(identity)
}

fn matches_github_actions_identity(
    identity: &IdentityConfig,
    claims: &GithubActionsClaims,
) -> bool {
    if identity.kind != IdentityKind::GithubActions
        || identity.repository_id.as_deref() != Some(claims.repository_id.as_str())
        || !identity
            .repository
            .as_ref()
            .is_none_or(|expected| expected.eq_ignore_ascii_case(&claims.repository))
    {
        return false;
    }

    // An Actions identity without a WorkflowPath is repository-wide. This is
    // permitted for non-signing policies, while config validation requires a
    // constrained WorkflowPath before the identity can receive sign authority.
    let Some(workflow_path) = identity.workflow_path.as_deref() else {
        return true;
    };

    let Some(allowed_events) = identity.allowed_event_names.as_ref() else {
        return false;
    };
    if !allowed_events
        .iter()
        .any(|event| event == &claims.event_name)
    {
        return false;
    }

    // Preserve the old nested-block default: constrained Actions identities
    // default to tag refs unless AllowedRefTypes is explicitly configured.
    if let Some(allowed_ref_types) = &identity.allowed_ref_types {
        if !allowed_ref_types
            .iter()
            .any(|ref_type| ref_type == &claims.ref_type)
        {
            return false;
        }
    } else if claims.ref_type != "tag" {
        return false;
    }

    let expected_workflow_ref =
        format!("{}/{}@{}", claims.repository, workflow_path, claims.git_ref);
    if claims.workflow_ref != expected_workflow_ref {
        return false;
    }

    if let Some(expected) = &identity.required_environment
        && claims.environment.as_deref() != Some(expected.as_str())
    {
        return false;
    }
    if let Some(expected) = &identity.required_runner_environment
        && claims.runner_environment.as_deref() != Some(expected.as_str())
    {
        return false;
    }
    if let Some(allowed_workflow_shas) = &identity.allowed_workflow_shas
        && !allowed_workflow_shas.is_empty()
    {
        let Some(workflow_sha) = claims.workflow_sha.as_ref() else {
            return false;
        };
        if !allowed_workflow_shas
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(workflow_sha))
        {
            return false;
        }
    }

    true
}

fn bearer_token(headers: &HeaderMap) -> Result<&str, AuthError> {
    let value = headers
        .get(AUTHORIZATION)
        .ok_or(AuthError::MissingBearer)?
        .to_str()
        .map_err(|_| AuthError::MissingBearer)?;
    if value.len() > MAX_BEARER_TOKEN_BYTES {
        return Err(AuthError::TokenTooLarge);
    }
    let (scheme, token) = value.split_once(' ').ok_or(AuthError::MissingBearer)?;
    if !scheme.eq_ignore_ascii_case("bearer")
        || token.is_empty()
        || token.chars().any(char::is_whitespace)
    {
        return Err(AuthError::MissingBearer);
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc as StdArc,
        atomic::{AtomicUsize, Ordering},
    };

    use axum::{
        Json, Router,
        extract::State,
        http::StatusCode,
        response::{IntoResponse, Response},
        routing::{get, post},
    };
    use serde_json::json;

    #[derive(Clone)]
    struct MockGithubState {
        check_status: StatusCode,
        token_client_id: String,
        scopes: Vec<String>,
        user_status: StatusCode,
        user_id: u64,
        login: String,
        two_factor_authentication: Option<bool>,
        revoke_status: StatusCode,
        revocations: StdArc<AtomicUsize>,
    }

    impl Default for MockGithubState {
        fn default() -> Self {
            Self {
                check_status: StatusCode::OK,
                token_client_id: "Iv1.test".into(),
                scopes: vec!["read:user".into()],
                user_status: StatusCode::OK,
                user_id: 42,
                login: "octocat".into(),
                two_factor_authentication: Some(true),
                revoke_status: StatusCode::NO_CONTENT,
                revocations: StdArc::new(AtomicUsize::new(0)),
            }
        }
    }

    async fn mock_token_check(State(state): State<MockGithubState>) -> Response {
        if state.check_status != StatusCode::OK {
            return state.check_status.into_response();
        }
        Json(json!({
            "scopes": state.scopes,
            "app": { "client_id": state.token_client_id },
        }))
        .into_response()
    }

    async fn mock_user(State(state): State<MockGithubState>) -> Response {
        if state.user_status != StatusCode::OK {
            return state.user_status.into_response();
        }
        Json(json!({
            "login": state.login,
            "id": state.user_id,
            "two_factor_authentication": state.two_factor_authentication,
        }))
        .into_response()
    }

    async fn mock_revoke(State(state): State<MockGithubState>) -> Response {
        state.revocations.fetch_add(1, Ordering::SeqCst);
        state.revoke_status.into_response()
    }

    async fn spawn_mock_github(state: MockGithubState) -> (String, tokio::task::JoinHandle<()>) {
        let app = Router::new()
            .route(
                "/applications/{client_id}/token",
                post(mock_token_check).delete(mock_revoke),
            )
            .route("/user", get(mock_user))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), task)
    }

    fn account_identity() -> IdentityConfig {
        IdentityConfig {
            id: "maintainer".into(),
            kind: IdentityKind::GithubAccount,
            github_user_id: Some("42".into()),
            github_login: Some("OctoCat".into()),
            repository_id: None,
            repository: None,
            workflow_path: None,
            allowed_event_names: None,
            allowed_ref_types: None,
            required_environment: None,
            required_runner_environment: None,
            allowed_workflow_shas: None,
        }
    }

    fn actions_identity() -> IdentityConfig {
        IdentityConfig {
            id: "release-actions".into(),
            kind: IdentityKind::GithubActions,
            github_user_id: None,
            github_login: None,
            repository_id: Some("123".into()),
            repository: Some("owner/repo".into()),
            workflow_path: Some(".github/workflows/release.yml".into()),
            allowed_event_names: Some(vec!["push".into()]),
            allowed_ref_types: Some(vec!["tag".into()]),
            required_environment: Some("firmware-signing".into()),
            required_runner_environment: None,
            allowed_workflow_shas: Some(vec!["fedcba9876543210".into()]),
        }
    }

    fn actions_claims() -> GithubActionsClaims {
        GithubActionsClaims {
            iss: GITHUB_ACTIONS_ISSUER.into(),
            aud: Audience::One("aud".into()),
            sub: "repo:owner/repo:ref:refs/tags/v1.2.3".into(),
            exp: 4_102_444_800,
            jti: Some("jti-1".into()),
            actor: Some("release-user".into()),
            actor_id: Some("456".into()),
            repository: "owner/repo".into(),
            repository_id: "123".into(),
            git_ref: "refs/tags/v1.2.3".into(),
            ref_type: "tag".into(),
            ref_protected: Some(serde_json::Value::Bool(true)),
            sha: "0123456789abcdef".into(),
            workflow_ref: "owner/repo/.github/workflows/release.yml@refs/tags/v1.2.3".into(),
            workflow_sha: Some("fedcba9876543210".into()),
            event_name: "push".into(),
            run_id: "42".into(),
            run_attempt: "1".into(),
            environment: Some("firmware-signing".into()),
            runner_environment: Some("github-hosted".into()),
        }
    }

    #[test]
    fn account_identity_uses_immutable_numeric_id() {
        let identity = account_identity();
        assert!(matches_github_account_identity(&identity, "42", "octocat"));
        assert!(!matches_github_account_identity(&identity, "43", "octocat"));
    }

    #[test]
    fn actions_identity_uses_repository_numeric_id() {
        let identity = actions_identity();
        let claims = actions_claims();
        assert!(matches_github_actions_identity(&identity, &claims));

        let mut wrong = claims.clone();
        wrong.repository_id = "124".into();
        assert!(!matches_github_actions_identity(&identity, &wrong));

        let mut wrong_workflow = claims.clone();
        wrong_workflow.workflow_ref =
            "owner/repo/.github/workflows/other.yml@refs/tags/v1.2.3".into();
        assert!(!matches_github_actions_identity(&identity, &wrong_workflow));

        let mut wrong_environment = claims.clone();
        wrong_environment.environment = Some("other".into());
        assert!(!matches_github_actions_identity(
            &identity,
            &wrong_environment
        ));
    }

    #[test]
    fn actions_identities_can_share_repository_when_workflows_differ() {
        let release = actions_identity();
        let mut nightly = actions_identity();
        nightly.id = "nightly-actions".into();
        nightly.workflow_path = Some(".github/workflows/nightly.yml".into());

        let claims = actions_claims();
        let identities = vec![release, nightly];
        let resolved = resolve_github_actions_identity(&identities, &claims).unwrap();
        assert_eq!(resolved.id, "release-actions");
    }

    #[test]
    fn overlapping_actions_identities_are_rejected_as_ambiguous() {
        let release = actions_identity();
        let mut duplicate = actions_identity();
        duplicate.id = "also-release-actions".into();

        let claims = actions_claims();
        let identities = vec![release, duplicate];
        assert!(matches!(
            resolve_github_actions_identity(&identities, &claims),
            Err(AuthError::ClaimsDenied)
        ));
    }

    fn test_authenticator() -> Authenticator {
        Authenticator::for_tests()
    }

    #[test]
    fn oauth_device_config_exposes_only_public_flow_parameters() {
        let auth = test_authenticator();
        let config = auth.github_oauth_device_config();
        assert_eq!(config.client_id, "Iv1.test");
        assert_eq!(
            config.device_code_url,
            "https://github.com/login/device/code"
        );
        assert_eq!(
            config.access_token_url,
            "https://github.com/login/oauth/access_token"
        );
        assert_eq!(config.scope, "read:user");
    }

    #[test]
    fn read_user_scope_is_required() {
        assert!(scope_grants_read_user(&["read:user".into()]));
        assert!(scope_grants_read_user(&["gist".into(), "user".into()]));
        assert!(!scope_grants_read_user(&[]));
        assert!(!scope_grants_read_user(&["read:org".into()]));
    }

    #[test]
    fn device_bootstrap_tokens_are_single_use() {
        let auth = test_authenticator();
        let first = auth.begin_device_token_use("gho_test").unwrap();
        assert!(matches!(
            auth.begin_device_token_use("gho_test"),
            Err(OAuthFlowError::TokenReplayed)
        ));
        first.mark_consumed().unwrap();
        drop(first);
        assert!(matches!(
            auth.begin_device_token_use("gho_test"),
            Err(OAuthFlowError::TokenReplayed)
        ));
    }

    #[tokio::test]
    async fn device_exchange_mints_session_only_after_successful_revocation() {
        let state = MockGithubState::default();
        let revocations = state.revocations.clone();
        let (api_url, task) = spawn_mock_github(state).await;
        let auth = Authenticator::for_tests_with_github(&api_url, vec![account_identity()]);

        let grant = auth
            .complete_github_device_oauth("gho_valid")
            .await
            .unwrap();
        assert!(grant.access_token.starts_with(SESSION_TOKEN_PREFIX));
        assert_eq!(revocations.load(Ordering::SeqCst), 1);

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            format!("Bearer {}", grant.access_token).parse().unwrap(),
        );
        let principal = auth.authenticate(&headers).await.unwrap();
        assert_eq!(principal.identity_id, "maintainer");
        assert!(matches!(
            auth.complete_github_device_oauth("gho_valid").await,
            Err(OAuthFlowError::TokenReplayed)
        ));
        task.abort();
    }

    #[tokio::test]
    async fn device_exchange_rejects_token_for_another_oauth_app() {
        let state = MockGithubState {
            token_client_id: "Iv1.someone-else".into(),
            ..MockGithubState::default()
        };
        let revocations = state.revocations.clone();
        let (api_url, task) = spawn_mock_github(state).await;
        let auth = Authenticator::for_tests_with_github(&api_url, vec![account_identity()]);

        assert!(matches!(
            auth.complete_github_device_oauth("gho_wrong_app").await,
            Err(OAuthFlowError::TokenValidationFailed)
        ));
        assert_eq!(revocations.load(Ordering::SeqCst), 0);
        task.abort();
    }

    #[tokio::test]
    async fn device_exchange_revokes_token_when_scope_is_missing() {
        let state = MockGithubState {
            scopes: vec!["read:org".into()],
            ..MockGithubState::default()
        };
        let revocations = state.revocations.clone();
        let (api_url, task) = spawn_mock_github(state).await;
        let auth = Authenticator::for_tests_with_github(&api_url, vec![account_identity()]);

        assert!(matches!(
            auth.complete_github_device_oauth("gho_no_scope").await,
            Err(OAuthFlowError::ScopeNotGranted)
        ));
        assert_eq!(revocations.load(Ordering::SeqCst), 1);
        task.abort();
    }

    #[tokio::test]
    async fn device_exchange_revokes_token_for_unauthorized_account() {
        let state = MockGithubState {
            user_id: 99,
            ..MockGithubState::default()
        };
        let revocations = state.revocations.clone();
        let (api_url, task) = spawn_mock_github(state).await;
        let auth = Authenticator::for_tests_with_github(&api_url, vec![account_identity()]);

        assert!(matches!(
            auth.complete_github_device_oauth("gho_unauthorized").await,
            Err(OAuthFlowError::ClaimsDenied)
        ));
        assert_eq!(revocations.load(Ordering::SeqCst), 1);
        task.abort();
    }

    #[tokio::test]
    async fn device_exchange_requires_two_factor_authentication() {
        let state = MockGithubState {
            two_factor_authentication: Some(false),
            ..MockGithubState::default()
        };
        let revocations = state.revocations.clone();
        let (api_url, task) = spawn_mock_github(state).await;
        let auth = Authenticator::for_tests_with_github(&api_url, vec![account_identity()]);

        assert!(matches!(
            auth.complete_github_device_oauth("gho_no_2fa").await,
            Err(OAuthFlowError::TwoFactorRequired)
        ));
        assert_eq!(revocations.load(Ordering::SeqCst), 1);
        task.abort();
    }

    #[tokio::test]
    async fn device_exchange_handles_github_token_check_failure() {
        let state = MockGithubState {
            check_status: StatusCode::INTERNAL_SERVER_ERROR,
            ..MockGithubState::default()
        };
        let revocations = state.revocations.clone();
        let (api_url, task) = spawn_mock_github(state).await;
        let auth = Authenticator::for_tests_with_github(&api_url, vec![account_identity()]);

        assert!(matches!(
            auth.complete_github_device_oauth("gho_github_failure")
                .await,
            Err(OAuthFlowError::IdentityProviderUnavailable)
        ));
        assert_eq!(revocations.load(Ordering::SeqCst), 0);
        task.abort();
    }

    #[tokio::test]
    async fn device_exchange_fails_closed_when_revocation_fails() {
        let state = MockGithubState {
            revoke_status: StatusCode::INTERNAL_SERVER_ERROR,
            ..MockGithubState::default()
        };
        let revocations = state.revocations.clone();
        let (api_url, task) = spawn_mock_github(state).await;
        let auth = Authenticator::for_tests_with_github(&api_url, vec![account_identity()]);

        assert!(matches!(
            auth.complete_github_device_oauth("gho_revoke_failure")
                .await,
            Err(OAuthFlowError::TokenRevocationFailed)
        ));
        assert!(auth.inner.oauth_sessions.read().await.is_empty());

        // A transient revocation failure must not poison the retained replay
        // cache: a later request may retry the fail-closed revocation step.
        assert!(matches!(
            auth.complete_github_device_oauth("gho_revoke_failure")
                .await,
            Err(OAuthFlowError::TokenRevocationFailed)
        ));
        assert_eq!(revocations.load(Ordering::SeqCst), 2);
        task.abort();
    }

    #[tokio::test]
    async fn session_tokens_are_random_and_stored_hashed() {
        let auth = test_authenticator();
        let token = format!(
            "{SESSION_TOKEN_PREFIX}{}",
            B64URL.encode(random_bytes::<32>())
        );
        assert_eq!(token.len(), 4 + 43);
        auth.inner.oauth_sessions.write().await.insert(
            session_key(&token),
            GithubAccountSession {
                expires_at: Instant::now() + Duration::from_secs(60),
                identity_id: "maintainer".into(),
                user_id: "42".into(),
                login: "octocat".into(),
            },
        );
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
        assert!(auth.authenticate(&headers).await.is_ok());
        assert!(
            !auth
                .inner
                .oauth_sessions
                .read()
                .await
                .keys()
                .any(|key| key.as_slice() == token.as_bytes())
        );
    }

    #[test]
    fn github_actions_jti_is_single_use() {
        let auth = test_authenticator();
        let exp = unix_now() + 300;
        auth.record_jti("abc", exp).unwrap();
        assert!(matches!(
            auth.record_jti("abc", exp),
            Err(AuthError::TokenReplayed)
        ));
        auth.record_jti("def", exp).unwrap();
    }

    #[test]
    fn ref_protected_accepts_bool_or_string() {
        use serde_json::Value;
        assert!(claim_is_true(Some(&Value::Bool(true))));
        assert!(claim_is_true(Some(&Value::String("true".into()))));
        assert!(!claim_is_true(Some(&Value::String("false".into()))));
        assert!(!claim_is_true(Some(&Value::Bool(false))));
        assert!(!claim_is_true(None));
    }

    #[tokio::test]
    async fn unknown_kid_does_not_refetch_within_the_refresh_interval() {
        let auth = test_authenticator();
        {
            let mut cache = auth.inner.jwks.write().await;
            cache.fetched_at = Some(Instant::now());
            cache.last_attempt = Some(Instant::now());
        }
        // A fetch would fail in this sandboxed test (and report KeyDiscovery);
        // an immediate InvalidToken shows no fetch was attempted.
        assert!(matches!(
            auth.jwk_for("unknown-kid").await,
            Err(AuthError::InvalidToken)
        ));
    }

    #[tokio::test]
    async fn stale_keys_are_served_when_refresh_is_not_allowed() {
        let auth = test_authenticator();
        {
            let mut cache = auth.inner.jwks.write().await;
            cache.fetched_at = Instant::now().checked_sub(Duration::from_secs(7200));
            cache.last_attempt = Some(Instant::now());
            cache.keys.insert(
                "kid".into(),
                RsaJwk {
                    kty: "RSA".into(),
                    kid: "kid".into(),
                    alg: Some("RS256".into()),
                    n: "AQAB".into(),
                    e: "AQAB".into(),
                    use_: Some("sig".into()),
                },
            );
        }
        assert!(auth.jwk_for("kid").await.is_ok());
    }
}
