use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::http::{HeaderMap, header::AUTHORIZATION};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{Mutex as AsyncMutex, RwLock};
use zeroize::Zeroizing;

use crate::{
    config::{GithubActionsConfig, GithubConfig, IdentityConfig, IdentityKind},
    key::load_systemd_credential,
    oauth::{Account, AuthorizationRequest, GrantError, OAuthStore, PendingLogin, TokenGrant},
};

const GITHUB_ACTIONS_ISSUER: &str = "https://token.actions.githubusercontent.com";
const GITHUB_ACCOUNT_ISSUER: &str = "https://github.com";
const MAX_BEARER_TOKEN_BYTES: usize = 16 * 1024;
const MAX_GITHUB_CODE_BYTES: usize = 1024;

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
/// Path below `Server.PublicURL` that GitHub redirects users back to. It must
/// be registered as the OAuth App's authorization callback URL.
pub const GITHUB_CALLBACK_PATH: &str = "/v1/auth/github/callback";

#[derive(Clone)]
pub struct Authenticator {
    inner: Arc<Inner>,
}

struct Inner {
    github: GithubConfig,
    github_oauth_client_secret: Zeroizing<String>,
    /// `<Server.PublicURL>/v1/auth/github/callback`.
    github_redirect_uri: String,
    actions: GithubActionsConfig,
    identities: Vec<IdentityConfig>,
    http: reqwest::Client,
    jwks: RwLock<JwksCache>,
    /// Serialises JWKS refreshes so concurrent cache misses cause one fetch.
    jwks_refresh: AsyncMutex<()>,
    /// Pending logins, authorization codes, and signer-local sessions.
    oauth: OAuthStore,
    seen_jtis: Mutex<HashMap<String, Instant>>,
}

#[derive(Default)]
struct JwksCache {
    fetched_at: Option<Instant>,
    last_attempt: Option<Instant>,
    keys: HashMap<String, RsaJwk>,
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

/// GitHub answers the code exchange with HTTP 200 for both outcomes: either
/// `access_token` and `scope`, or an OAuth `error`.
#[derive(Deserialize)]
struct GithubTokenResponse {
    access_token: Option<String>,
    scope: Option<String>,
    error: Option<String>,
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

/// Why a GitHub sign-in did not produce a signer authorization code. The
/// messages are shown to the user by the CLI.
#[derive(Debug, Error)]
pub enum OAuthFlowError {
    #[error("GitHub sign-in was cancelled or denied")]
    AuthorizationDenied,
    #[error("GitHub rejected the authorization code")]
    CodeExchangeFailed,
    #[error("GitHub did not grant the read:user scope needed to verify two-factor authentication")]
    ScopeNotGranted,
    #[error("GitHub is temporarily unavailable")]
    IdentityProviderUnavailable,
    #[error("the temporary GitHub token could not be revoked, so no signer session was issued")]
    TokenRevocationFailed,
    #[error("this GitHub account is not a configured signer identity")]
    ClaimsDenied,
    #[error("this GitHub account does not have two-factor authentication enabled")]
    TwoFactorRequired,
    #[error("the signer is handling too many sign-ins right now")]
    Capacity,
}

impl Authenticator {
    pub fn new(
        public_url: &str,
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
            .user_agent(concat!("microtun-signer/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self::assemble(
            public_url,
            github,
            github_oauth_client_secret,
            actions,
            identities,
            http,
        ))
    }

    fn assemble(
        public_url: &str,
        github: GithubConfig,
        github_oauth_client_secret: Zeroizing<String>,
        actions: GithubActionsConfig,
        identities: Vec<IdentityConfig>,
        http: reqwest::Client,
    ) -> Self {
        let oauth = OAuthStore::new(
            Duration::from_secs(github.oauth_session_ttl_seconds),
            (github.oauth_refresh_ttl_seconds != 0)
                .then(|| Duration::from_secs(github.oauth_refresh_ttl_seconds)),
        );
        Self {
            inner: Arc::new(Inner {
                github,
                github_oauth_client_secret,
                github_redirect_uri: format!("{public_url}{GITHUB_CALLBACK_PATH}"),
                actions,
                identities,
                http,
                jwks: RwLock::new(JwksCache::default()),
                jwks_refresh: AsyncMutex::new(()),
                oauth,
                seen_jtis: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Start a login for a validated CLI authorization request and return the
    /// GitHub URL the user's browser must be sent to.
    pub fn begin_github_login(
        &self,
        request: AuthorizationRequest,
    ) -> Result<reqwest::Url, OAuthFlowError> {
        let github = &self.inner.github;
        let mut url = reqwest::Url::parse(&github.oauth_authorize_url)
            .map_err(|_| OAuthFlowError::IdentityProviderUnavailable)?;
        let (state, code_challenge) = self
            .inner
            .oauth
            .begin_login(request)
            .map_err(|_| OAuthFlowError::Capacity)?;
        url.query_pairs_mut()
            .append_pair("client_id", &github.oauth_client_id)
            .append_pair("redirect_uri", &self.inner.github_redirect_uri)
            .append_pair("scope", OAUTH_SCOPE)
            .append_pair("state", &state)
            .append_pair("code_challenge", &code_challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("allow_signup", "false");
        Ok(url)
    }

    /// Consume the login that GitHub's `state` parameter refers to.
    pub fn take_pending_login(&self, state: &str) -> Option<PendingLogin> {
        if state.len() > MAX_GITHUB_CODE_BYTES {
            return None;
        }
        self.inner.oauth.take_pending_login(state)
    }

    /// Turn GitHub's authorization code into a signer authorization code for
    /// the CLI. The GitHub token obtained on the way must resolve to a
    /// configured 2FA-enabled account and is revoked at GitHub before
    /// anything is issued; it is never stored and never leaves the signer.
    pub async fn finish_github_login(
        &self,
        pending: &PendingLogin,
        github_code: &str,
    ) -> Result<(String, Account), OAuthFlowError> {
        if github_code.is_empty() || github_code.len() > MAX_GITHUB_CODE_BYTES {
            return Err(OAuthFlowError::CodeExchangeFailed);
        }
        let (github_token, granted_scopes) = self
            .exchange_github_code(github_code, &pending.github_code_verifier)
            .await?;

        let outcome = self
            .github_account_from_token(&github_token, &granted_scopes)
            .await;

        // Revocation is fail-closed. Even a valid configured account receives
        // no signer session unless the GitHub credential is gone.
        self.revoke_github_token(&github_token).await?;

        let account = outcome?;
        let code = self
            .inner
            .oauth
            .issue_code(&pending.request, account.clone())
            .map_err(|_| OAuthFlowError::Capacity)?;
        Ok((code, account))
    }

    /// Token endpoint, `grant_type=authorization_code`.
    pub fn redeem_authorization_code(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<(TokenGrant, Account), GrantError> {
        if code.len() > MAX_BEARER_TOKEN_BYTES {
            return Err(GrantError::Invalid);
        }
        self.inner
            .oauth
            .redeem_code(code, redirect_uri, code_verifier)
    }

    /// Token endpoint, `grant_type=refresh_token`.
    ///
    /// This does not go back to GitHub: the GitHub token was revoked at login.
    /// How long a login may be extended this way is bounded by
    /// `GitHub.OAuthRefreshTTLSeconds`.
    pub fn refresh_session(
        &self,
        refresh_token: &str,
    ) -> Result<(TokenGrant, Account), GrantError> {
        if refresh_token.len() > MAX_BEARER_TOKEN_BYTES {
            return Err(GrantError::Invalid);
        }
        self.inner.oauth.refresh(refresh_token)
    }

    /// Revocation endpoint: ends the login the token belongs to.
    pub fn revoke_session(&self, token: &str) -> Option<Account> {
        if token.len() > MAX_BEARER_TOKEN_BYTES {
            return None;
        }
        self.inner.oauth.revoke(token)
    }

    pub async fn authenticate(&self, headers: &HeaderMap) -> Result<AuthPrincipal, AuthError> {
        let token = bearer_token(headers)?;

        // GitHub Actions OIDC tokens are JWTs. All other accepted credentials
        // must be signer-local access tokens minted by our own OAuth flow;
        // arbitrary GitHub OAuth/App bearer tokens are deliberately rejected.
        if is_github_actions_jwt(token) {
            self.authenticate_github_actions(token).await
        } else {
            self.authenticate_github_account_session(token)
        }
    }

    fn authenticate_github_account_session(&self, token: &str) -> Result<AuthPrincipal, AuthError> {
        let account = self
            .inner
            .oauth
            .authenticate(token)
            .ok_or(AuthError::InvalidToken)?;

        Ok(AuthPrincipal {
            identity_id: account.identity_id,
            principal_key: format!("github-account:{}", account.user_id),
            auth_method: "github-oauth-session",
            issuer: GITHUB_ACCOUNT_ISSUER.to_owned(),
            audience: Some(self.inner.github.oauth_client_id.clone()),
            subject: account.user_id.clone(),
            jti: None,
            source: AuthSource::GithubAccount(GithubAccountIdentity {
                user_id: account.user_id,
                login: account.login,
            }),
        })
    }

    /// Exchange GitHub's authorization code as a confidential client. Only
    /// the holder of the client secret can do this, so the resulting token is
    /// known to belong to this exact OAuth App.
    async fn exchange_github_code(
        &self,
        code: &str,
        code_verifier: &str,
    ) -> Result<(Zeroizing<String>, Vec<String>), OAuthFlowError> {
        let github = &self.inner.github;
        let response = self
            .inner
            .http
            .post(&github.oauth_access_token_url)
            .header("Accept", "application/json")
            .form(&[
                ("client_id", github.oauth_client_id.as_str()),
                (
                    "client_secret",
                    self.inner.github_oauth_client_secret.as_str(),
                ),
                ("code", code),
                ("redirect_uri", self.inner.github_redirect_uri.as_str()),
                ("code_verifier", code_verifier),
            ])
            .send()
            .await
            .map_err(|_| OAuthFlowError::IdentityProviderUnavailable)?;
        if !response.status().is_success() {
            return Err(OAuthFlowError::IdentityProviderUnavailable);
        }
        let body = response
            .json::<GithubTokenResponse>()
            .await
            .map_err(|_| OAuthFlowError::IdentityProviderUnavailable)?;
        let token = Zeroizing::new(body.access_token.unwrap_or_default());
        if body.error.is_some() {
            return Err(OAuthFlowError::CodeExchangeFailed);
        }
        if token.is_empty() {
            return Err(OAuthFlowError::IdentityProviderUnavailable);
        }
        let scopes = body
            .scope
            .unwrap_or_default()
            .split([',', ' '])
            .filter(|scope| !scope.is_empty())
            .map(str::to_owned)
            .collect();
        Ok((token, scopes))
    }

    /// Resolve a GitHub OAuth token to a configured identity whose account
    /// has two-factor authentication enabled.
    async fn github_account_from_token(
        &self,
        token: &str,
        granted_scopes: &[String],
    ) -> Result<Account, OAuthFlowError> {
        if !scope_grants_read_user(granted_scopes) {
            return Err(OAuthFlowError::ScopeNotGranted);
        }

        let user = self
            .resolve_github_user(token)
            .await
            .map_err(|error| match error {
                AuthError::InvalidToken => OAuthFlowError::CodeExchangeFailed,
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
        Ok(Account {
            identity_id: identity.id.clone(),
            user_id,
            login: user.login,
        })
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

    /// Revoke the GitHub token before issuing anything signer-local.
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
        Self::for_tests_with_github(
            "https://api.github.com",
            "https://signer.example.com",
            Vec::new(),
        )
    }

    /// `github_url` stands in for both github.com and api.github.com.
    pub(crate) fn for_tests_with_github(
        github_url: &str,
        public_url: &str,
        identities: Vec<IdentityConfig>,
    ) -> Self {
        let github: GithubConfig = toml::from_str(&format!(
            r#"APIURL = "{github_url}"
OAuthAuthorizeURL = "{github_url}/login/oauth/authorize"
OAuthAccessTokenURL = "{github_url}/login/oauth/access_token"
OAuthClientID = "Iv1.test"
"#
        ))
        .expect("test GitHub config");
        let actions: GithubActionsConfig = toml::from_str("").expect("test Actions config");
        Self::assemble(
            public_url,
            github,
            Zeroizing::new("secret".into()),
            actions,
            identities,
            reqwest::Client::new(),
        )
    }
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
    use axum::http::StatusCode;

    use crate::{
        oauth::{ACCESS_TOKEN_PREFIX, REFRESH_TOKEN_PREFIX},
        test_github::{MockGithub, code_for_authorize_url, query_param},
    };

    const PUBLIC_URL: &str = "https://signer.example.com";
    const CLI_REDIRECT_URI: &str = "http://127.0.0.1:49152/callback";
    const CLI_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CLI_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    fn cli_request() -> AuthorizationRequest {
        AuthorizationRequest::new(CLI_REDIRECT_URI, "cli-state", CLI_CHALLENGE).unwrap()
    }

    fn bearer(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
        headers
    }

    /// Drive the server side of a login up to the point where GitHub has
    /// redirected the browser back to the signer.
    async fn github_login(
        github: MockGithub,
    ) -> (
        Authenticator,
        Result<(String, Account), OAuthFlowError>,
        tokio::task::JoinHandle<()>,
    ) {
        let (github_url, task) = github.spawn().await;
        let auth =
            Authenticator::for_tests_with_github(&github_url, PUBLIC_URL, vec![account_identity()]);
        let authorize_url = auth.begin_github_login(cli_request()).unwrap();
        let state = query_param(&authorize_url, "state").unwrap();
        let pending = auth.take_pending_login(&state).unwrap();
        let outcome = auth
            .finish_github_login(&pending, &code_for_authorize_url(&authorize_url))
            .await;
        (auth, outcome, task)
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
    fn github_authorize_url_carries_the_confidential_client_parameters() {
        let auth = test_authenticator();
        let url = auth.begin_github_login(cli_request()).unwrap();
        assert!(
            url.as_str()
                .starts_with("https://api.github.com/login/oauth/authorize?")
        );
        assert_eq!(query_param(&url, "client_id").as_deref(), Some("Iv1.test"));
        assert_eq!(
            query_param(&url, "redirect_uri").as_deref(),
            Some("https://signer.example.com/v1/auth/github/callback")
        );
        assert_eq!(query_param(&url, "scope").as_deref(), Some("read:user"));
        assert_eq!(
            query_param(&url, "code_challenge_method").as_deref(),
            Some("S256")
        );
        // GitHub's leg has its own state and PKCE pair: the CLI's values and
        // the client secret never appear in the browser's GitHub URL.
        assert_ne!(query_param(&url, "state").as_deref(), Some("cli-state"));
        assert_ne!(
            query_param(&url, "code_challenge").as_deref(),
            Some(CLI_CHALLENGE)
        );
        assert!(!url.as_str().contains("secret"));
    }

    #[test]
    fn read_user_scope_is_required() {
        assert!(scope_grants_read_user(&["read:user".into()]));
        assert!(scope_grants_read_user(&["gist".into(), "user".into()]));
        assert!(!scope_grants_read_user(&[]));
        assert!(!scope_grants_read_user(&["read:org".into()]));
    }

    #[tokio::test]
    async fn login_issues_tokens_only_after_revoking_the_github_token() {
        let github = MockGithub::default();
        let (auth, outcome, task) = github_login(github.clone()).await;
        let (code, account) = outcome.unwrap();
        assert_eq!(account.identity_id, "maintainer");
        assert_eq!(github.exchanges(), 1);
        assert_eq!(github.revocations(), 1);

        let (tokens, _) = auth
            .redeem_authorization_code(&code, CLI_REDIRECT_URI, CLI_VERIFIER)
            .unwrap();
        assert!(tokens.access_token.starts_with(ACCESS_TOKEN_PREFIX));
        let refresh_token = tokens.refresh_token.unwrap();
        assert!(refresh_token.starts_with(REFRESH_TOKEN_PREFIX));

        let principal = auth
            .authenticate(&bearer(&tokens.access_token))
            .await
            .unwrap();
        assert_eq!(principal.identity_id, "maintainer");
        assert_eq!(principal.principal_key, "github-account:42");
        assert_eq!(principal.auth_method, "github-oauth-session");

        // Refreshing is local: GitHub is not contacted again.
        let (refreshed, _) = auth.refresh_session(&refresh_token).unwrap();
        assert!(
            auth.authenticate(&bearer(&refreshed.access_token))
                .await
                .is_ok()
        );
        assert_eq!(github.exchanges(), 1);

        // A refresh token is not a bearer credential for the signing API.
        assert!(matches!(
            auth.authenticate(&bearer(&refresh_token)).await,
            Err(AuthError::InvalidToken)
        ));

        assert!(auth.revoke_session(&refreshed.access_token).is_some());
        assert!(matches!(
            auth.authenticate(&bearer(&refreshed.access_token)).await,
            Err(AuthError::InvalidToken)
        ));
        task.abort();
    }

    #[tokio::test]
    async fn github_state_is_single_use() {
        let auth = test_authenticator();
        let url = auth.begin_github_login(cli_request()).unwrap();
        let state = query_param(&url, "state").unwrap();
        assert!(auth.take_pending_login(&state).is_some());
        assert!(auth.take_pending_login(&state).is_none());
        assert!(auth.take_pending_login("forged").is_none());
    }

    #[tokio::test]
    async fn login_rejects_a_code_github_does_not_accept() {
        let github = MockGithub::default();
        let (github_url, task) = github.clone().spawn().await;
        let auth =
            Authenticator::for_tests_with_github(&github_url, PUBLIC_URL, vec![account_identity()]);
        let url = auth.begin_github_login(cli_request()).unwrap();
        let pending = auth
            .take_pending_login(&query_param(&url, "state").unwrap())
            .unwrap();

        assert!(matches!(
            auth.finish_github_login(&pending, "ghcode_forged").await,
            Err(OAuthFlowError::CodeExchangeFailed)
        ));
        assert_eq!(github.revocations(), 0);
        task.abort();
    }

    #[tokio::test]
    async fn login_revokes_token_when_scope_is_missing() {
        let github = MockGithub {
            scope: "read:org".into(),
            ..MockGithub::default()
        };
        let (_auth, outcome, task) = github_login(github.clone()).await;
        assert!(matches!(outcome, Err(OAuthFlowError::ScopeNotGranted)));
        assert_eq!(github.revocations(), 1);
        task.abort();
    }

    #[tokio::test]
    async fn login_revokes_token_for_unauthorized_account() {
        let github = MockGithub {
            user_id: 99,
            ..MockGithub::default()
        };
        let (_auth, outcome, task) = github_login(github.clone()).await;
        assert!(matches!(outcome, Err(OAuthFlowError::ClaimsDenied)));
        assert_eq!(github.revocations(), 1);
        task.abort();
    }

    #[tokio::test]
    async fn login_requires_two_factor_authentication() {
        for two_factor_authentication in [Some(false), None] {
            let github = MockGithub {
                two_factor_authentication,
                ..MockGithub::default()
            };
            let (_auth, outcome, task) = github_login(github.clone()).await;
            assert!(matches!(outcome, Err(OAuthFlowError::TwoFactorRequired)));
            assert_eq!(github.revocations(), 1);
            task.abort();
        }
    }

    #[tokio::test]
    async fn login_handles_github_code_exchange_outage() {
        let github = MockGithub {
            exchange_status: StatusCode::INTERNAL_SERVER_ERROR,
            ..MockGithub::default()
        };
        let (_auth, outcome, task) = github_login(github.clone()).await;
        assert!(matches!(
            outcome,
            Err(OAuthFlowError::IdentityProviderUnavailable)
        ));
        assert_eq!(github.revocations(), 0);
        task.abort();
    }

    #[tokio::test]
    async fn login_fails_closed_when_revocation_fails() {
        let github = MockGithub {
            revoke_status: StatusCode::INTERNAL_SERVER_ERROR,
            ..MockGithub::default()
        };
        let (_auth, outcome, task) = github_login(github.clone()).await;
        assert!(matches!(
            outcome,
            Err(OAuthFlowError::TokenRevocationFailed)
        ));
        assert_eq!(github.revocations(), 1);
        task.abort();
    }

    #[tokio::test]
    async fn github_tokens_are_not_accepted_as_bearer_credentials() {
        let auth = test_authenticator();
        assert!(matches!(
            auth.authenticate(&bearer("gho_mock")).await,
            Err(AuthError::InvalidToken)
        ));
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
