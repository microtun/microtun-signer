//! Loading and validating the firmware signer TOML configuration.
//!
//! Authentication proves a configured identity. Authorization policies then
//! grant those identities operations on immutable signing keys. GitHub account
//! and GitHub Actions credentials are merely two ways of proving identities.

use std::{
    collections::{HashMap, HashSet},
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

const CONFIG_API_VERSION_ID: &str = "microtun.dev/v1alpha1";
const CONFIG_KIND: &str = "FirmwareSignerConfig";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(rename = "Microtun")]
    pub microtun: MicrotunConfig,
    #[serde(rename = "Server")]
    pub server: ServerConfig,
    #[serde(rename = "Unlock", default)]
    pub unlock: UnlockConfig,
    #[serde(rename = "Key")]
    pub keys: Vec<KeyConfig>,
    #[serde(rename = "GitHub")]
    pub github: GithubConfig,
    #[serde(rename = "GitHubActions")]
    pub github_actions: GithubActionsConfig,
    #[serde(rename = "Identity", default)]
    pub identities: Vec<IdentityConfig>,
    #[serde(rename = "Policy", default)]
    pub policies: Vec<PolicyConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MicrotunConfig {
    #[serde(rename = "ApiVersion")]
    pub api_version: String,
    #[serde(rename = "Kind")]
    pub kind: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[serde(rename = "Listen")]
    pub listen: SocketAddr,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnlockConfig {
    #[serde(rename = "SocketPath", default = "default_unlock_socket_path")]
    pub socket_path: PathBuf,
    #[serde(rename = "SocketMode", default = "default_unlock_socket_mode")]
    pub socket_mode: u32,
}

impl Default for UnlockConfig {
    fn default() -> Self {
        Self {
            socket_path: default_unlock_socket_path(),
            socket_mode: default_unlock_socket_mode(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyConfig {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "PEMPath")]
    pub pem_path: PathBuf,
    #[serde(rename = "State", default)]
    pub state: KeyState,
    // Accepted only to produce an explicit migration error. Key passphrases
    // are no longer loaded from environment/files/systemd credentials.
    #[serde(rename = "PassphraseCredential", default)]
    pub passphrase_credential: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum KeyState {
    #[default]
    Active,
    Disabled,
    Retired,
}

impl KeyState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
            Self::Retired => "retired",
        }
    }
}

/// GitHub OAuth application and REST API settings for human identities.
///
/// The signer is the confidential OAuth client: it owns the client secret,
/// performs the authorization-code exchange, resolves the authenticated user,
/// and then issues its own short-lived bearer session. GitHub access tokens are
/// never accepted directly by the signing API.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubConfig {
    #[serde(rename = "APIURL", default = "default_github_api_url")]
    pub api_url: String,
    #[serde(rename = "APIVersion", default = "default_github_api_version")]
    pub api_version: String,
    #[serde(
        rename = "OAuthAuthorizeURL",
        default = "default_github_oauth_authorize_url"
    )]
    pub oauth_authorize_url: String,
    #[serde(
        rename = "OAuthAccessTokenURL",
        default = "default_github_oauth_access_token_url"
    )]
    pub oauth_access_token_url: String,
    #[serde(rename = "OAuthClientID")]
    pub oauth_client_id: String,
    #[serde(
        rename = "OAuthClientSecretCredential",
        default = "default_github_oauth_client_secret_credential"
    )]
    pub oauth_client_secret_credential: String,
    #[serde(rename = "OAuthCallbackURL")]
    pub oauth_callback_url: String,
    #[serde(
        rename = "OAuthSessionTTLSeconds",
        default = "default_oauth_session_ttl_seconds"
    )]
    pub oauth_session_ttl_seconds: u64,
    #[serde(
        rename = "OAuthStateTTLSeconds",
        default = "default_oauth_state_ttl_seconds"
    )]
    pub oauth_state_ttl_seconds: u64,
}

/// GitHub Actions OIDC verifier infrastructure. Repository/workflow trust is
/// deliberately not configured here; that belongs to identity definitions.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubActionsConfig {
    #[serde(rename = "Audience", default = "default_audience")]
    pub audience: String,
    #[serde(rename = "JWKSURL", default = "default_jwks_url")]
    pub jwks_url: String,
    #[serde(rename = "JWKSTTLSeconds", default = "default_jwks_ttl_seconds")]
    pub jwks_ttl_seconds: u64,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum IdentityKind {
    GithubAccount,
    GithubActions,
}

/// A named identity is a stable external GitHub subject. Policies reference the
/// local ID, while authentication matches immutable GitHub numeric IDs.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "Type")]
    pub kind: IdentityKind,

    // github-account
    #[serde(rename = "GitHubUserID")]
    pub github_user_id: Option<String>,
    #[serde(rename = "GitHubLogin")]
    pub github_login: Option<String>,

    // github-actions. These repository/workflow claim constraints are kept
    // directly on the identity because together they define the Actions
    // security principal that policies authorize.
    #[serde(rename = "RepositoryID")]
    pub repository_id: Option<String>,
    #[serde(rename = "Repository")]
    pub repository: Option<String>,
    #[serde(rename = "WorkflowPath")]
    pub workflow_path: Option<String>,
    #[serde(rename = "AllowedEventNames")]
    pub allowed_event_names: Option<Vec<String>>,
    #[serde(rename = "AllowedRefTypes")]
    pub allowed_ref_types: Option<Vec<String>>,
    #[serde(rename = "RequiredEnvironment")]
    pub required_environment: Option<String>,
    #[serde(rename = "RequiredRunnerEnvironment")]
    pub required_runner_environment: Option<String>,
    #[serde(rename = "AllowedWorkflowSHAs")]
    pub allowed_workflow_shas: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyAction {
    Sign,
}

impl PolicyAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sign => "sign",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    #[serde(rename = "Identity")]
    pub identity: String,
    #[serde(rename = "Actions")]
    pub actions: Vec<PolicyAction>,
    #[serde(rename = "Keys")]
    pub keys: Vec<String>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        let mut config: Self = toml::from_str(&text)
            .with_context(|| format!("failed to parse config {}", path.display()))?;
        config.normalize_and_validate()?;
        Ok(config)
    }

    fn normalize_and_validate(&mut self) -> Result<()> {
        if self.microtun.api_version != CONFIG_API_VERSION_ID {
            bail!(
                "unsupported config ApiVersion {} (expected {CONFIG_API_VERSION_ID})",
                self.microtun.api_version
            );
        }
        if self.microtun.kind != CONFIG_KIND {
            bail!(
                "unsupported config Kind {} (expected {CONFIG_KIND})",
                self.microtun.kind
            );
        }

        if !self.unlock.socket_path.is_absolute() {
            bail!("Unlock.SocketPath must be an absolute path");
        }
        if self.unlock.socket_mode > 0o777
            || self.unlock.socket_mode & 0o600 != 0o600
            || self.unlock.socket_mode & 0o007 != 0
        {
            bail!(
                "Unlock.SocketMode must grant owner read/write, must not grant access to other users, and must fit within 0777"
            );
        }

        if self.keys.is_empty() {
            bail!("at least one [[Key]] must be configured");
        }
        let mut key_ids = HashSet::with_capacity(self.keys.len());
        for key in &self.keys {
            if !valid_key_id(&key.id) {
                bail!("Key.ID must match [A-Za-z0-9._-]{{1,128}}");
            }
            if !key_ids.insert(key.id.as_str()) {
                bail!("duplicate Key.ID {}", key.id);
            }
            if key.passphrase_credential.is_some() {
                bail!(
                    "Key.PassphraseCredential is no longer supported; signing keys start locked and must be unlocked through the local unlock API"
                );
            }
        }

        if !self.github.api_url.starts_with("https://") || self.github.api_url.ends_with('/') {
            bail!("GitHub.APIURL must be an https:// URL without a trailing slash");
        }
        if self.github.api_version.trim().is_empty() {
            bail!("GitHub.APIVersion must not be empty");
        }
        validate_https_url("GitHub.OAuthAuthorizeURL", &self.github.oauth_authorize_url)?;
        validate_https_url(
            "GitHub.OAuthAccessTokenURL",
            &self.github.oauth_access_token_url,
        )?;
        if self.github.oauth_client_id.trim().is_empty() {
            bail!("GitHub.OAuthClientID must not be empty");
        }
        if !valid_credential_name(&self.github.oauth_client_secret_credential) {
            bail!("GitHub.OAuthClientSecretCredential must match [A-Za-z0-9._-]{{1,128}}");
        }
        let callback =
            validate_https_url("GitHub.OAuthCallbackURL", &self.github.oauth_callback_url)?;
        if callback.query().is_some() || callback.fragment().is_some() {
            bail!("GitHub.OAuthCallbackURL must not contain a query string or fragment");
        }
        if callback.path() != "/v1/auth/github/callback" {
            bail!("GitHub.OAuthCallbackURL path must be /v1/auth/github/callback");
        }
        if self.github.oauth_session_ttl_seconds == 0
            || self.github.oauth_session_ttl_seconds > 24 * 60 * 60
        {
            bail!("GitHub.OAuthSessionTTLSeconds must be between 1 and 86400 seconds");
        }
        if self.github.oauth_state_ttl_seconds == 0 || self.github.oauth_state_ttl_seconds > 600 {
            bail!("GitHub.OAuthStateTTLSeconds must be between 1 and 600 seconds");
        }

        if self.github_actions.audience.trim().is_empty() {
            bail!("GitHubActions.Audience must not be empty");
        }
        if !self.github_actions.jwks_url.starts_with("https://") {
            bail!("GitHubActions.JWKSURL must use https://");
        }
        if self.github_actions.jwks_ttl_seconds == 0 {
            bail!("GitHubActions.JWKSTTLSeconds must be greater than zero");
        }

        if self.identities.is_empty() {
            bail!("at least one [[Identity]] must be configured");
        }
        let mut identity_ids = HashSet::with_capacity(self.identities.len());
        let mut github_accounts = HashSet::new();
        let mut identity_kinds = HashMap::with_capacity(self.identities.len());

        for identity in &self.identities {
            if !valid_identity_id(&identity.id) {
                bail!("Identity.ID must match [A-Za-z0-9._-]{{1,128}}");
            }
            if !identity_ids.insert(identity.id.as_str()) {
                bail!("duplicate Identity.ID {}", identity.id);
            }

            match identity.kind {
                IdentityKind::GithubAccount => {
                    let user_id = identity.github_user_id.as_deref().ok_or_else(|| {
                        anyhow::anyhow!(
                            "Identity {} of type github-account requires GitHubUserID",
                            identity.id
                        )
                    })?;
                    validate_numeric_id("Identity.GitHubUserID", user_id)?;
                    if !github_accounts.insert(user_id) {
                        bail!("duplicate github-account GitHubUserID {user_id}");
                    }
                    if identity.repository_id.is_some()
                        || identity.repository.is_some()
                        || identity.workflow_path.is_some()
                        || identity.allowed_event_names.is_some()
                        || identity.allowed_ref_types.is_some()
                        || identity.required_environment.is_some()
                        || identity.required_runner_environment.is_some()
                        || identity.allowed_workflow_shas.is_some()
                    {
                        bail!(
                            "Identity {} of type github-account must not set GitHub Actions repository/workflow fields",
                            identity.id
                        );
                    }
                    if identity
                        .github_login
                        .as_ref()
                        .is_some_and(|login| login.trim().is_empty())
                    {
                        bail!("Identity.GitHubLogin must not be empty when set");
                    }
                }
                IdentityKind::GithubActions => {
                    let repository_id = identity.repository_id.as_deref().ok_or_else(|| {
                        anyhow::anyhow!(
                            "Identity {} of type github-actions requires RepositoryID",
                            identity.id
                        )
                    })?;
                    validate_numeric_id("Identity.RepositoryID", repository_id)?;
                    if identity.github_user_id.is_some() || identity.github_login.is_some() {
                        bail!(
                            "Identity {} of type github-actions must not set GitHubUserID/GitHubLogin",
                            identity.id
                        );
                    }
                    if identity
                        .repository
                        .as_ref()
                        .is_some_and(|repo| !valid_repository(repo))
                    {
                        bail!("Identity.Repository must be in owner/name form when set");
                    }
                    validate_actions_identity(identity)?;
                }
            }
            identity_kinds.insert(identity.id.as_str(), identity.kind);
        }

        if self.policies.is_empty() {
            bail!("at least one [[Policy]] must be configured");
        }
        for policy in &self.policies {
            let Some(identity_kind) = identity_kinds.get(policy.identity.as_str()).copied() else {
                bail!(
                    "Policy.Identity {} does not name a configured identity",
                    policy.identity
                );
            };
            if policy.actions.is_empty() {
                bail!("Policy.Actions must not be empty");
            }
            if policy.keys.is_empty() {
                bail!("Policy.Keys must not be empty");
            }
            let mut seen_actions = HashSet::new();
            for action in &policy.actions {
                if !seen_actions.insert(*action) {
                    bail!("Policy.Actions contains duplicate {}", action.as_str());
                }
            }
            let mut seen_keys = HashSet::new();
            for key in &policy.keys {
                if key != "*" && !key_ids.contains(key.as_str()) {
                    bail!("Policy.Keys references unknown key {key}");
                }
                if !seen_keys.insert(key.as_str()) {
                    bail!("Policy.Keys contains duplicate key {key}");
                }
            }

            if identity_kind == IdentityKind::GithubActions
                && policy.actions.contains(&PolicyAction::Sign)
            {
                let identity = self
                    .identities
                    .iter()
                    .find(|identity| identity.id == policy.identity)
                    .expect("validated identity reference");
                if identity.workflow_path.is_none() {
                    bail!(
                        "sign policy for github-actions identity {} requires Identity.WorkflowPath and claim constraints",
                        policy.identity
                    );
                }
            }
        }

        Ok(())
    }
}

fn validate_actions_identity(identity: &IdentityConfig) -> Result<()> {
    let has_claim_constraints = identity.workflow_path.is_some()
        || identity.allowed_event_names.is_some()
        || identity.allowed_ref_types.is_some()
        || identity.required_environment.is_some()
        || identity.required_runner_environment.is_some()
        || identity.allowed_workflow_shas.is_some();

    if !has_claim_constraints {
        return Ok(());
    }

    let workflow_path = identity.workflow_path.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "Identity.WorkflowPath is required when GitHub Actions claim constraints are configured"
        )
    })?;
    if workflow_path.starts_with('/')
        || !workflow_path.starts_with(".github/workflows/")
        || workflow_path.contains("..")
    {
        bail!("Identity.WorkflowPath must name a file below .github/workflows/");
    }

    let events = identity.allowed_event_names.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "Identity.AllowedEventNames is required when GitHub Actions claim constraints are configured"
        )
    })?;
    if events.is_empty() || events.iter().any(|value| value.trim().is_empty()) {
        bail!("Identity.AllowedEventNames must not be empty or contain empty values");
    }

    if let Some(ref_types) = &identity.allowed_ref_types {
        if ref_types.is_empty() || ref_types.iter().any(|value| value.trim().is_empty()) {
            bail!("Identity.AllowedRefTypes must not be empty or contain empty values");
        }
    }
    if identity
        .required_environment
        .as_ref()
        .is_some_and(|value| value.trim().is_empty())
    {
        bail!("Identity.RequiredEnvironment must not be empty when set");
    }
    if identity
        .required_runner_environment
        .as_ref()
        .is_some_and(|value| value.trim().is_empty())
    {
        bail!("Identity.RequiredRunnerEnvironment must not be empty when set");
    }
    if identity
        .allowed_workflow_shas
        .as_ref()
        .is_some_and(|values| values.iter().any(|value| value.trim().is_empty()))
    {
        bail!("Identity.AllowedWorkflowSHAs must not contain empty values");
    }
    Ok(())
}

fn validate_https_url(field: &str, value: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(value).with_context(|| format!("{field} must be a valid URL"))?;
    if url.scheme() != "https" || url.host_str().is_none() {
        bail!("{field} must use https:// and include a host");
    }
    Ok(url)
}

fn validate_numeric_id(field: &str, value: &str) -> Result<()> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        bail!("{field} must be a numeric GitHub id");
    }
    Ok(())
}

fn valid_repository(value: &str) -> bool {
    let Some((owner, name)) = value.split_once('/') else {
        return false;
    };
    !owner.is_empty() && !name.is_empty() && !name.contains('/')
}

pub fn valid_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn valid_identity_id(value: &str) -> bool {
    valid_key_id(value)
}

fn valid_credential_name(value: &str) -> bool {
    valid_key_id(value)
}

fn default_unlock_socket_path() -> PathBuf {
    PathBuf::from("/run/microtun-firmware-signer/unlock.sock")
}

const fn default_unlock_socket_mode() -> u32 {
    0o660
}

fn default_github_api_url() -> String {
    "https://api.github.com".to_owned()
}

fn default_github_api_version() -> String {
    "2026-03-10".to_owned()
}

fn default_github_oauth_authorize_url() -> String {
    "https://github.com/login/oauth/authorize".to_owned()
}

fn default_github_oauth_access_token_url() -> String {
    "https://github.com/login/oauth/access_token".to_owned()
}

fn default_github_oauth_client_secret_credential() -> String {
    "github-oauth-client-secret".to_owned()
}

const fn default_oauth_session_ttl_seconds() -> u64 {
    8 * 60 * 60
}

const fn default_oauth_state_ttl_seconds() -> u64 {
    10 * 60
}

fn default_audience() -> String {
    "microtun-firmware-signer".to_owned()
}

fn default_jwks_url() -> String {
    "https://token.actions.githubusercontent.com/.well-known/jwks".to_owned()
}

const fn default_jwks_ttl_seconds() -> u64 {
    3600
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config(extra: &str) -> String {
        format!(
            r#"[Microtun]
ApiVersion = "microtun.dev/v1alpha1"
Kind = "FirmwareSignerConfig"

[Server]
Listen = "127.0.0.1:8080"

[[Key]]
ID = "test-key"
PEMPath = "/tmp/test-key.pem"

[GitHub]
OAuthClientID = "Iv1.test-client-id"
OAuthCallbackURL = "https://signer.example/v1/auth/github/callback"

[GitHubActions]

{extra}
"#
        )
    }

    #[test]
    fn oauth_callback_must_use_root_api_path() {
        let text = base_config(
            r#"[[Identity]]
ID = "maintainer"
Type = "github-account"
GitHubUserID = "42"

[[Policy]]
Identity = "maintainer"
Actions = ["sign"]
Keys = ["test-key"]
"#,
        )
        .replace(
            "https://signer.example/v1/auth/github/callback",
            "https://signer.example/legacy-prefix/v1/auth/github/callback",
        );
        let mut config: Config = toml::from_str(&text).unwrap();
        let error = config.normalize_and_validate().unwrap_err().to_string();
        assert!(error.contains("must be /v1/auth/github/callback"));
    }

    #[test]
    fn key_ids_match_protocol() {
        assert!(valid_key_id("microtun-firmware-prod-2026-01"));
        assert!(!valid_key_id(""));
        assert!(!valid_key_id("bad/key"));
        assert!(!valid_key_id(&"a".repeat(129)));
    }

    #[test]
    fn unlock_socket_defaults_to_local_runtime_path() {
        let text = base_config(
            r#"[[Identity]]
ID = "maintainer"
Type = "github-account"
GitHubUserID = "42"

[[Policy]]
Identity = "maintainer"
Actions = ["sign"]
Keys = ["test-key"]
"#,
        );
        let mut config: Config = toml::from_str(&text).unwrap();
        config.normalize_and_validate().unwrap();
        assert_eq!(
            config.unlock.socket_path,
            PathBuf::from("/run/microtun-firmware-signer/unlock.sock")
        );
        assert_eq!(config.unlock.socket_mode, 0o660);
    }

    #[test]
    fn key_passphrase_credential_is_rejected() {
        let text = base_config(
            r#"[[Identity]]
ID = "maintainer"
Type = "github-account"
GitHubUserID = "42"

[[Policy]]
Identity = "maintainer"
Actions = ["sign"]
Keys = ["test-key"]
"#,
        )
        .replace(
            "PEMPath = \"/tmp/test-key.pem\"",
            "PEMPath = \"/tmp/test-key.pem\"\nPassphraseCredential = \"signing-key-passphrase\"",
        );
        let mut config: Config = toml::from_str(&text).unwrap();
        let error = config.normalize_and_validate().unwrap_err().to_string();
        assert!(error.contains("no longer supported"));
    }

    #[test]
    fn account_identity_and_key_policy_validate() {
        let text = base_config(
            r#"[[Identity]]
ID = "maintainer"
Type = "github-account"
GitHubUserID = "42"
GitHubLogin = "octocat"

[[Policy]]
Identity = "maintainer"
Actions = ["sign"]
Keys = ["test-key"]
"#,
        );
        let mut config: Config = toml::from_str(&text).unwrap();
        config.normalize_and_validate().unwrap();
    }

    #[test]
    fn get_key_is_not_a_policy_action() {
        let text = base_config(
            r#"[[Identity]]
ID = "maintainer"
Type = "github-account"
GitHubUserID = "42"

[[Policy]]
Identity = "maintainer"
Actions = ["get-key"]
Keys = ["test-key"]
"#,
        );
        assert!(toml::from_str::<Config>(&text).is_err());
    }

    #[test]
    fn actions_sign_policy_requires_identity_conditions() {
        let text = base_config(
            r#"[[Identity]]
ID = "release-actions"
Type = "github-actions"
RepositoryID = "123"

[[Policy]]
Identity = "release-actions"
Actions = ["sign"]
Keys = ["test-key"]
"#,
        );
        let mut config: Config = toml::from_str(&text).unwrap();
        let error = config.normalize_and_validate().unwrap_err().to_string();
        assert!(error.contains("requires Identity.WorkflowPath"));
    }

    #[test]
    fn actions_identity_with_conditions_validates() {
        let text = base_config(
            r#"[[Identity]]
ID = "release-actions"
Type = "github-actions"
RepositoryID = "123"
Repository = "owner/repo"

WorkflowPath = ".github/workflows/release.yml"
AllowedEventNames = ["push"]
AllowedRefTypes = ["tag"]

[[Policy]]
Identity = "release-actions"
Actions = ["sign"]
Keys = ["test-key"]
"#,
        );
        let mut config: Config = toml::from_str(&text).unwrap();
        config.normalize_and_validate().unwrap();
    }

    #[test]
    fn policy_cannot_reference_unknown_key() {
        let text = base_config(
            r#"[[Identity]]
ID = "maintainer"
Type = "github-account"
GitHubUserID = "42"

[[Policy]]
Identity = "maintainer"
Actions = ["sign"]
Keys = ["missing"]
"#,
        );
        let mut config: Config = toml::from_str(&text).unwrap();
        assert!(config.normalize_and_validate().is_err());
    }

    #[test]
    fn actions_identities_may_share_repository_id() {
        let text = base_config(
            r#"[[Identity]]
ID = "release-actions"
Type = "github-actions"
RepositoryID = "123"
WorkflowPath = ".github/workflows/release.yml"
AllowedEventNames = ["push"]
AllowedRefTypes = ["tag"]

[[Identity]]
ID = "nightly-actions"
Type = "github-actions"
RepositoryID = "123"
WorkflowPath = ".github/workflows/nightly.yml"
AllowedEventNames = ["schedule"]
AllowedRefTypes = ["branch"]

[[Policy]]
Identity = "release-actions"
Actions = ["sign"]
Keys = ["test-key"]

[[Policy]]
Identity = "nightly-actions"
Actions = ["sign"]
Keys = ["test-key"]
"#,
        );
        let mut config: Config = toml::from_str(&text).unwrap();
        config.normalize_and_validate().unwrap();
    }

    #[test]
    fn duplicate_external_identities_are_rejected() {
        let text = base_config(
            r#"[[Identity]]
ID = "one"
Type = "github-account"
GitHubUserID = "42"

[[Identity]]
ID = "two"
Type = "github-account"
GitHubUserID = "42"

[[Policy]]
Identity = "one"
Actions = ["sign"]
Keys = ["test-key"]
"#,
        );
        let mut config: Config = toml::from_str(&text).unwrap();
        assert!(config.normalize_and_validate().is_err());
    }
}
