use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::http::{HeaderMap, header::AUTHORIZATION};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use thiserror::Error;
use tokio::sync::RwLock;
use ulid::Ulid;
use zeroize::Zeroizing;

use crate::{
    config::{GithubActionsConfig, GithubConfig, IdentityConfig, IdentityKind},
    key::load_required_secret,
};

const GITHUB_ACTIONS_ISSUER: &str = "https://token.actions.githubusercontent.com";
const GITHUB_ACCOUNT_ISSUER: &str = "https://github.com";
const MAX_BEARER_TOKEN_BYTES: usize = 16 * 1024;
const MAX_OAUTH_SESSIONS: usize = 4096;
const MAX_PENDING_OAUTH_STATES: usize = 1024;

pub const GITHUB_OAUTH_CLIENT_SECRET_ENV: &str = "MICROTUN_SIGNER_GITHUB_OAUTH_CLIENT_SECRET";
pub const GITHUB_OAUTH_CLIENT_SECRET_FILE_ENV: &str =
    "MICROTUN_SIGNER_GITHUB_OAUTH_CLIENT_SECRET_FILE";

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
    oauth_states: RwLock<HashMap<String, Instant>>,
    oauth_sessions: RwLock<HashMap<String, GithubAccountSession>>,
}

#[derive(Default)]
struct JwksCache {
    fetched_at: Option<Instant>,
    keys: HashMap<String, RsaJwk>,
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
    pub jti: Option<String>,
    pub actor: Option<String>,
    pub actor_id: Option<String>,
    pub repository: String,
    pub repository_id: String,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub ref_type: String,
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
}

#[derive(Debug, Deserialize)]
struct GithubOAuthTokenResponse {
    access_token: Option<String>,
    token_type: Option<String>,
    error: Option<String>,
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
    pub sha: String,
    pub workflow_ref: String,
    pub event_name: String,
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
pub struct OAuthSessionGrant {
    pub access_token: String,
    pub expires_in: u64,
    pub identity_id: String,
    pub user_id: String,
    pub login: String,
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("authorization bearer token is missing or malformed")]
    MissingBearer,
    #[error("bearer token is too large")]
    TokenTooLarge,
    #[error("bearer token is invalid or expired")]
    InvalidToken,
    #[error("GitHub Actions OIDC key discovery failed")]
    KeyDiscovery,
    #[error("GitHub identity provider is temporarily unavailable")]
    IdentityProviderUnavailable,
    #[error("authenticated GitHub subject does not match a configured identity")]
    ClaimsDenied,
}

#[derive(Debug, Error)]
pub enum OAuthFlowError {
    #[error("GitHub OAuth state is invalid or expired")]
    InvalidState,
    #[error("GitHub OAuth authorization was denied")]
    AuthorizationDenied,
    #[error("GitHub OAuth code exchange failed")]
    ExchangeFailed,
    #[error("GitHub identity provider is temporarily unavailable")]
    IdentityProviderUnavailable,
    #[error("authenticated GitHub account does not match a configured identity")]
    ClaimsDenied,
    #[error("too many OAuth sessions are active")]
    SessionCapacity,
    #[error("too many OAuth login attempts are pending")]
    StateCapacity,
}

impl Authenticator {
    pub fn new(
        github: GithubConfig,
        actions: GithubActionsConfig,
        identities: Vec<IdentityConfig>,
    ) -> anyhow::Result<Self> {
        let github_oauth_client_secret = load_required_secret(
            GITHUB_OAUTH_CLIENT_SECRET_ENV,
            GITHUB_OAUTH_CLIENT_SECRET_FILE_ENV,
            &github.oauth_client_secret_credential,
            "GitHub OAuth client secret",
        )?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("microtun-firmware-signer/0.1")
            .build()?;
        Ok(Self {
            inner: Arc::new(Inner {
                github,
                github_oauth_client_secret,
                actions,
                identities,
                http,
                jwks: RwLock::new(JwksCache::default()),
                oauth_states: RwLock::new(HashMap::new()),
                oauth_sessions: RwLock::new(HashMap::new()),
            }),
        })
    }

    /// Start the signer's own GitHub OAuth web flow. The returned URL is the
    /// only place a human account should obtain authorization for this service.
    pub async fn github_oauth_authorize_url(&self) -> Result<String, OAuthFlowError> {
        let now = Instant::now();
        let mut states = self.inner.oauth_states.write().await;
        let ttl = Duration::from_secs(self.inner.github.oauth_state_ttl_seconds);
        states.retain(|_, created_at| now.duration_since(*created_at) < ttl);
        if states.len() >= MAX_PENDING_OAUTH_STATES {
            return Err(OAuthFlowError::StateCapacity);
        }

        let state = opaque_token("state_");
        states.insert(state.clone(), now);
        drop(states);

        let mut url = reqwest::Url::parse(&self.inner.github.oauth_authorize_url)
            .map_err(|_| OAuthFlowError::IdentityProviderUnavailable)?;
        url.query_pairs_mut()
            .append_pair("client_id", &self.inner.github.oauth_client_id)
            .append_pair("redirect_uri", &self.inner.github.oauth_callback_url)
            .append_pair("state", &state);
        Ok(url.to_string())
    }

    /// Finish the signer's GitHub OAuth flow and mint a signer-local bearer
    /// session. The GitHub access token is used once to resolve the account and
    /// is never returned to the caller or retained in the session store.
    pub async fn complete_github_oauth(
        &self,
        code: &str,
        state: &str,
    ) -> Result<OAuthSessionGrant, OAuthFlowError> {
        if code.is_empty() || state.is_empty() {
            return Err(OAuthFlowError::AuthorizationDenied);
        }
        self.consume_oauth_state(state).await?;

        let response = self
            .inner
            .http
            .post(&self.inner.github.oauth_access_token_url)
            .header("Accept", "application/json")
            .form(&[
                ("client_id", self.inner.github.oauth_client_id.as_str()),
                (
                    "client_secret",
                    self.inner.github_oauth_client_secret.as_str(),
                ),
                ("code", code),
                (
                    "redirect_uri",
                    self.inner.github.oauth_callback_url.as_str(),
                ),
            ])
            .send()
            .await
            .map_err(|_| OAuthFlowError::IdentityProviderUnavailable)?;

        if !response.status().is_success() {
            return Err(OAuthFlowError::ExchangeFailed);
        }
        let exchanged = response
            .json::<GithubOAuthTokenResponse>()
            .await
            .map_err(|_| OAuthFlowError::ExchangeFailed)?;
        if exchanged.error.is_some() {
            return Err(OAuthFlowError::ExchangeFailed);
        }
        let access_token = Zeroizing::new(
            exchanged
                .access_token
                .ok_or(OAuthFlowError::ExchangeFailed)?,
        );
        if exchanged
            .token_type
            .as_deref()
            .is_some_and(|value| !value.eq_ignore_ascii_case("bearer"))
        {
            return Err(OAuthFlowError::ExchangeFailed);
        }

        let user = self
            .resolve_github_user(access_token.as_str())
            .await
            .map_err(|error| match error {
                AuthError::ClaimsDenied => OAuthFlowError::ClaimsDenied,
                AuthError::InvalidToken => OAuthFlowError::ExchangeFailed,
                _ => OAuthFlowError::IdentityProviderUnavailable,
            })?;
        let user_id = user.id.to_string();
        let identity = self
            .inner
            .identities
            .iter()
            .find(|identity| matches_github_account_identity(identity, &user_id, &user.login))
            .ok_or(OAuthFlowError::ClaimsDenied)?;

        let now = Instant::now();
        let expires_in = self.inner.github.oauth_session_ttl_seconds;
        let session = GithubAccountSession {
            expires_at: now + Duration::from_secs(expires_in),
            identity_id: identity.id.clone(),
            user_id: user_id.clone(),
            login: user.login.clone(),
        };
        let access_token = opaque_token("mts_");

        let mut sessions = self.inner.oauth_sessions.write().await;
        sessions.retain(|_, session| session.expires_at > now);
        if sessions.len() >= MAX_OAUTH_SESSIONS {
            return Err(OAuthFlowError::SessionCapacity);
        }
        sessions.insert(access_token.clone(), session);

        Ok(OAuthSessionGrant {
            access_token,
            expires_in,
            identity_id: identity.id.clone(),
            user_id,
            login: user.login,
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
        if !token.starts_with("mts_") {
            return Err(AuthError::InvalidToken);
        }

        let now = Instant::now();
        let mut sessions = self.inner.oauth_sessions.write().await;
        sessions.retain(|_, session| session.expires_at > now);
        let session = sessions
            .get(token)
            .cloned()
            .ok_or(AuthError::InvalidToken)?;
        drop(sessions);

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

    async fn consume_oauth_state(&self, state: &str) -> Result<(), OAuthFlowError> {
        let now = Instant::now();
        let ttl = Duration::from_secs(self.inner.github.oauth_state_ttl_seconds);
        let mut states = self.inner.oauth_states.write().await;
        states.retain(|_, created_at| now.duration_since(*created_at) < ttl);
        let created_at = states.remove(state).ok_or(OAuthFlowError::InvalidState)?;
        if now.duration_since(created_at) >= ttl {
            return Err(OAuthFlowError::InvalidState);
        }
        Ok(())
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
        validation.leeway = 60;
        validation.validate_nbf = true;
        validation.set_audience(&[actions.audience.as_str()]);
        validation.set_issuer(&[GITHUB_ACTIONS_ISSUER]);
        validation.set_required_spec_claims(&["exp", "nbf", "iss", "aud", "sub"]);

        let data = decode::<GithubActionsClaims>(token, &decoding_key, &validation)
            .map_err(|_| AuthError::InvalidToken)?;
        let claims = data.claims;
        let identity = resolve_github_actions_identity(&self.inner.identities, &claims)?;

        Ok(AuthPrincipal {
            identity_id: identity.id.clone(),
            principal_key: format!("github-actions:repository:{}", claims.repository_id),
            auth_method: "github-actions-oidc",
            issuer: claims.iss.clone(),
            audience: Some(claims.aud.as_audit_string()),
            subject: claims.sub.clone(),
            jti: claims.jti.clone(),
            source: AuthSource::GithubActions(Box::new(GithubActionsIdentity {
                repository: claims.repository,
                repository_id: claims.repository_id,
                actor: claims.actor,
                actor_id: claims.actor_id,
                git_ref: claims.git_ref,
                ref_type: claims.ref_type,
                sha: claims.sha,
                workflow_ref: claims.workflow_ref,
                event_name: claims.event_name,
                run_id: claims.run_id,
                run_attempt: claims.run_attempt,
            })),
        })
    }

    async fn jwk_for(&self, kid: &str) -> Result<RsaJwk, AuthError> {
        let actions = &self.inner.actions;
        {
            let cache = self.inner.jwks.read().await;
            let fresh = cache
                .fetched_at
                .is_some_and(|at| at.elapsed() < Duration::from_secs(actions.jwks_ttl_seconds));
            if fresh {
                if let Some(key) = cache.keys.get(kid) {
                    return Ok(key.clone());
                }
            }
        }

        self.refresh_jwks().await?;
        let cache = self.inner.jwks.read().await;
        cache.keys.get(kid).cloned().ok_or(AuthError::InvalidToken)
    }

    async fn refresh_jwks(&self) -> Result<(), AuthError> {
        let response = self
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
            .is_some_and(|length| length > 256 * 1024)
        {
            return Err(AuthError::KeyDiscovery);
        }
        let document = response
            .json::<JwksDocument>()
            .await
            .map_err(|_| AuthError::KeyDiscovery)?;

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

        let mut cache = self.inner.jwks.write().await;
        cache.keys = keys;
        cache.fetched_at = Some(Instant::now());
        Ok(())
    }
}

fn opaque_token(prefix: &str) -> String {
    // Each ULID contributes 80 random bits in addition to its timestamp. Two
    // independent ULIDs therefore provide 160 random bits for bearer/state use.
    format!("{prefix}{}_{}", Ulid::new(), Ulid::new())
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

    if let Some(expected) = &identity.required_environment {
        if claims.environment.as_deref() != Some(expected.as_str()) {
            return false;
        }
    }
    if let Some(expected) = &identity.required_runner_environment {
        if claims.runner_environment.as_deref() != Some(expected.as_str()) {
            return false;
        }
    }
    if let Some(allowed_workflow_shas) = &identity.allowed_workflow_shas {
        if !allowed_workflow_shas.is_empty() {
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
            jti: None,
            actor: Some("release-user".into()),
            actor_id: Some("456".into()),
            repository: "owner/repo".into(),
            repository_id: "123".into(),
            git_ref: "refs/tags/v1.2.3".into(),
            ref_type: "tag".into(),
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

    #[test]
    fn signer_session_tokens_are_not_github_tokens() {
        let token = opaque_token("mts_");
        assert!(token.starts_with("mts_"));
        assert!(token.len() > 50);
        assert_eq!(token.split('.').count(), 1);
    }
}
