use std::{env, time::Duration};

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use clap::Args;
use oauth2::basic::BasicClient;
use oauth2::{
    ClientId, DeviceAuthorizationUrl, Scope, StandardDeviceAuthorizationResponse, TokenResponse,
    TokenUrl,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{session_cache, valid_key_id};

#[derive(Debug, Args)]
pub struct SignArgs {
    /// Immutable signing key ID to use.
    #[arg(short = 'k', long = "key-id")]
    key_id: String,

    /// Bearer credential accepted by the signer. Prefer MICROTUN_SIGNER_TOKEN
    /// over --token so the credential is not exposed in the process list.
    #[arg(long, env = "MICROTUN_SIGNER_TOKEN", hide_env_values = true)]
    token: Option<String>,

    /// Authenticate as a GitHub user, reusing a cached signer session when
    /// available. If login is required, GitHub's OAuth device flow is used.
    /// This takes precedence over MICROTUN_SIGNER_TOKEN/--token.
    #[arg(long = "github-login", conflicts_with = "github_actions")]
    github_login: bool,

    /// Request a fresh GitHub Actions OIDC token for this signing operation.
    /// Requires a workflow/job with `id-token: write` permission and takes
    /// precedence over MICROTUN_SIGNER_TOKEN/--token.
    #[arg(long = "github-actions", conflicts_with = "github_login")]
    github_actions: bool,

    /// OIDC audience, matching the signer's GitHubActions.Audience setting.
    /// Defaults to "microtun-signer"; only valid with --github-actions.
    #[arg(long, requires = "github_actions")]
    audience: Option<String>,

    /// 32-byte MCUboot SHA-256 digest encoded as base64.
    #[arg(short = 'd', long)]
    digest: String,
}

#[derive(Debug, Args)]
pub struct PublicKeyArgs {
    /// Immutable signing key ID to fetch.
    #[arg(short = 'k', long = "key-id")]
    key_id: String,
}

#[derive(Serialize)]
struct SignRequest<'a> {
    digest: &'a str,
}

#[derive(Deserialize)]
struct SignResponse {
    signature: String,
}

#[derive(Deserialize)]
struct GithubActionsOidcResponse {
    value: String,
}

const DEFAULT_GITHUB_ACTIONS_AUDIENCE: &str = "microtun-signer";

#[derive(Deserialize)]
struct OAuthDeviceConfigResponse {
    client_id: String,
    device_code_url: String,
    access_token_url: String,
    scope: String,
}

#[derive(Serialize)]
struct OAuthDeviceExchangeRequest<'a> {
    access_token: &'a str,
}

#[derive(Deserialize)]
struct OAuthSessionResponse {
    access_token: String,
    expires_in: u64,
}

#[derive(Deserialize)]
struct ErrorBody {
    error: String,
    request_id: String,
}

pub async fn sign(url: &str, args: SignArgs) -> Result<()> {
    validate_key_id(&args.key_id)?;
    let decoded = BASE64
        .decode(args.digest.as_bytes())
        .context("--digest must be valid base64")?;
    if decoded.len() != 32 {
        bail!("--digest must decode to exactly 32 bytes");
    }

    let base_url = signer_base_url(url)?;
    let endpoint = base_url
        .join(&format!("v1/sign/{}", args.key_id))
        .context("failed to construct signing API URL")?;
    let client = public_api_client()?;

    // GitHub injects these variables only into jobs with OIDC permission. Prefer
    // an explicitly selected authentication method when one was provided.
    let use_actions = should_use_github_actions(
        args.github_actions,
        args.github_login,
        args.token.is_some(),
        env::var_os("ACTIONS_ID_TOKEN_REQUEST_URL").is_some(),
    );
    let (mut token, reused_cached_session) = if args.github_login {
        let cached = match session_cache::load(&base_url) {
            Ok(cached) => cached,
            Err(error) => {
                eprintln!("Warning: could not read signer session cache: {error:#}");
                None
            }
        };
        match cached {
            Some(token) => (token, true),
            None => (github_device_login(&client, &base_url).await?, false),
        }
    } else if use_actions {
        (
            github_actions_token(
                &client,
                args.audience
                    .as_deref()
                    .unwrap_or(DEFAULT_GITHUB_ACTIONS_AUDIENCE),
            )
            .await?,
            false,
        )
    } else if let Some(token) = args.token {
        if token.is_empty() {
            bail!("--token must not be empty");
        }
        (Zeroizing::new(token), false)
    } else {
        bail!(
            "no bearer credential was provided; set MICROTUN_SIGNER_TOKEN/--token, pass --github-login, or use --github-actions in a GitHub Actions job with id-token: write permission"
        );
    };

    let mut response =
        send_signing_request(&client, &endpoint, token.as_str(), &args.digest).await?;
    if response.status() == reqwest::StatusCode::UNAUTHORIZED
        && args.github_login
        && reused_cached_session
    {
        if let Err(error) = session_cache::remove(&base_url) {
            eprintln!("Warning: could not remove stale signer session cache: {error:#}");
        }
        eprintln!("Cached signer session is no longer accepted; authenticating with GitHub again.");
        token = github_device_login(&client, &base_url).await?;
        response = send_signing_request(&client, &endpoint, token.as_str(), &args.digest).await?;
    }
    if !response.status().is_success() {
        return Err(response_error(response, "signing request").await);
    }

    let signed: SignResponse = response
        .json()
        .await
        .context("signing API returned an invalid success response")?;
    let signature = BASE64
        .decode(signed.signature.as_bytes())
        .context("signing API returned a non-base64 signature")?;
    if signature.is_empty() {
        bail!("signing API returned an empty signature");
    }

    println!("{}", signed.signature);
    Ok(())
}

pub async fn public_key(url: &str, args: PublicKeyArgs) -> Result<()> {
    validate_key_id(&args.key_id)?;

    let base_url = signer_base_url(url)?;
    let endpoint = base_url
        .join(&format!("v1/public-key/{}", args.key_id))
        .context("failed to construct public-key API URL")?;
    let client = public_api_client()?;
    let response = client
        .get(endpoint)
        .send()
        .await
        .context("failed to call public-key API")?;
    if !response.status().is_success() {
        return Err(response_error(response, "public-key request").await);
    }

    let pem = response
        .text()
        .await
        .context("public-key API returned a non-text response")?;
    if !pem.starts_with("-----BEGIN PUBLIC KEY-----")
        || !pem.trim_end().ends_with("-----END PUBLIC KEY-----")
    {
        bail!("public-key API returned an invalid PEM public key");
    }

    print!("{pem}");
    if !pem.ends_with('\n') {
        println!();
    }
    Ok(())
}

fn validate_key_id(value: &str) -> Result<()> {
    if !valid_key_id(value) {
        bail!("--key-id must match [A-Za-z0-9._-]{{1,128}}");
    }
    Ok(())
}

async fn send_signing_request(
    client: &reqwest::Client,
    endpoint: &reqwest::Url,
    token: &str,
    digest: &str,
) -> Result<reqwest::Response> {
    client
        .post(endpoint.clone())
        .bearer_auth(token)
        .json(&SignRequest { digest })
        .send()
        .await
        .context("failed to call signing API")
}

fn signer_base_url(value: &str) -> Result<reqwest::Url> {
    let mut base_url = reqwest::Url::parse(value).context("--url must be a valid URL")?;
    if !matches!(base_url.scheme(), "http" | "https") {
        bail!("--url must use http or https");
    }
    if base_url.cannot_be_a_base() {
        bail!("--url must be a hierarchical http(s) URL");
    }
    if !base_url.path().ends_with('/') {
        let path = format!("{}/", base_url.path());
        base_url.set_path(&path);
    }
    Ok(base_url)
}

fn public_api_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("microtun-signer/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("failed to create Microtun signer API client")
}

fn should_use_github_actions(
    explicit: bool,
    github_login: bool,
    has_bearer_token: bool,
    has_oidc_request_url: bool,
) -> bool {
    explicit || (!github_login && !has_bearer_token && has_oidc_request_url)
}

fn github_actions_request_url(request_url: &str, audience: &str) -> Result<reqwest::Url> {
    if audience.trim().is_empty() {
        bail!("--audience must not be empty");
    }

    let mut url = reqwest::Url::parse(request_url)
        .context("ACTIONS_ID_TOKEN_REQUEST_URL must be a valid HTTPS URL")?;
    // Never send the runner's request bearer token over plaintext, to a URL
    // with embedded credentials, or to a redirect (the API client rejects all
    // redirects). GitHub supplies the trusted endpoint via the runner.
    if url.scheme() != "https"
        || url.cannot_be_a_base()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        bail!("ACTIONS_ID_TOKEN_REQUEST_URL must be a hierarchical HTTPS URL without credentials or a fragment");
    }
    if url.query_pairs().any(|(key, _)| key == "audience") {
        bail!("ACTIONS_ID_TOKEN_REQUEST_URL must not already specify an audience");
    }
    // Retain GitHub's existing query parameters, such as api-version=2.0,
    // and safely percent-encode the requested audience.
    url.query_pairs_mut().append_pair("audience", audience);
    Ok(url)
}

async fn github_actions_token(
    client: &reqwest::Client,
    audience: &str,
) -> Result<Zeroizing<String>> {
    let request_url = env::var("ACTIONS_ID_TOKEN_REQUEST_URL").context(
        "ACTIONS_ID_TOKEN_REQUEST_URL is missing; run in GitHub Actions with id-token: write permission",
    )?;
    let request_token = Zeroizing::new(env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").context(
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN is missing; ensure the job has id-token: write permission",
    )?);
    if request_token.is_empty() {
        bail!("ACTIONS_ID_TOKEN_REQUEST_TOKEN is empty");
    }
    let endpoint = github_actions_request_url(&request_url, audience)?;
    let response = client
        .get(endpoint)
        .bearer_auth(request_token.as_str())
        .send()
        .await
        // reqwest errors may embed the runner's credential-bearing request URL.
        // Keep that URL out of CLI diagnostics and CI logs.
        .map_err(|error| {
            anyhow::anyhow!(
                "failed to request GitHub Actions OIDC token: {}",
                error.without_url()
            )
        })?;
    if !response.status().is_success() {
        return Err(response_error(response, "GitHub Actions OIDC token request").await);
    }
    let oidc: GithubActionsOidcResponse = response.json().await.map_err(|error| {
        anyhow::anyhow!(
            "GitHub Actions returned an invalid OIDC token response: {}",
            error.without_url()
        )
    })?;
    if oidc.value.is_empty() {
        bail!("GitHub Actions returned an empty OIDC token");
    }
    Ok(Zeroizing::new(oidc.value))
}

async fn github_device_login(
    client: &reqwest::Client,
    signer_base_url: &reqwest::Url,
) -> Result<Zeroizing<String>> {
    let config_endpoint = signer_base_url
        .join("v1/auth/github/device")
        .context("failed to construct GitHub device-auth API URL")?;
    let response = client
        .get(config_endpoint.clone())
        .send()
        .await
        .context("failed to request GitHub device-flow configuration from signer")?;
    if !response.status().is_success() {
        return Err(response_error(response, "GitHub device authentication setup").await);
    }
    let config: OAuthDeviceConfigResponse = response
        .json()
        .await
        .context("signer returned invalid GitHub device-flow configuration")?;
    if config.client_id.is_empty() || config.scope.is_empty() {
        bail!("signer returned incomplete GitHub device-flow configuration");
    }

    // Validate signer-provided OAuth endpoints before giving them to oauth2. The
    // CLI is a public OAuth client; it never receives the OAuth client secret.
    let device_code_url = https_oauth_url(&config.device_code_url, "device-code")?;
    let access_token_url = https_oauth_url(&config.access_token_url, "access-token")?;
    let oauth = BasicClient::new(ClientId::new(config.client_id))
        .set_device_authorization_url(
            DeviceAuthorizationUrl::new(device_code_url.to_string())
                .context("signer returned an invalid GitHub device-code URL")?,
        )
        .set_token_uri(
            TokenUrl::new(access_token_url.to_string())
                .context("signer returned an invalid GitHub access-token URL")?,
        );

    let oauth_http = |request| github_oauth_http_request(client, request);
    let scopes = config
        .scope
        .split_ascii_whitespace()
        .map(|scope| Scope::new(scope.to_owned()));
    let device: StandardDeviceAuthorizationResponse = oauth
        .exchange_device_code()
        .add_scopes(scopes)
        .request_async(&oauth_http)
        .await
        .context("failed to start GitHub device authentication")?;

    eprintln!("GitHub authentication required.");
    eprintln!(
        "Open {} and enter code {}",
        device.verification_uri(),
        device.user_code().secret()
    );

    // oauth2 handles the RFC 8628 polling loop, but starts with an immediate token
    // request. GitHub requires the advertised interval to elapse before that first
    // request, so preserve that wait here and let the crate handle subsequent
    // authorization_pending/slow_down responses and expiry.
    let initial_poll_interval = device.interval();
    let poll_timeout = device.expires_in().saturating_sub(initial_poll_interval);
    tokio::time::sleep(initial_poll_interval).await;
    let token = oauth
        .exchange_device_access_token(&device)
        .request_async(&oauth_http, tokio::time::sleep, Some(poll_timeout))
        .await
        .context("GitHub device authentication failed")?;
    let github_access_token = Zeroizing::new(token.access_token().secret().to_owned());
    if github_access_token.is_empty() {
        bail!("GitHub returned an empty OAuth access token");
    }

    // Hand the GitHub token to the signer exactly once. The signer proves it
    // belongs to its OAuth App with the client secret, resolves the configured
    // identity and 2FA status, revokes the GitHub token, and returns an mts_ token.
    let response = client
        .post(config_endpoint)
        .json(&OAuthDeviceExchangeRequest {
            access_token: github_access_token.as_str(),
        })
        .send()
        .await
        .context("failed to exchange GitHub device token with signer")?;
    if !response.status().is_success() {
        return Err(response_error(response, "GitHub device token exchange").await);
    }
    let session: OAuthSessionResponse = response
        .json()
        .await
        .context("signer returned an invalid OAuth session response")?;
    if session.access_token.is_empty() || session.expires_in == 0 {
        bail!("signer returned an invalid OAuth session");
    }
    let cached =
        match session_cache::store(signer_base_url, &session.access_token, session.expires_in) {
            Ok(cached) => cached,
            Err(error) => {
                eprintln!("Warning: could not cache signer session: {error:#}");
                false
            }
        };

    if cached {
        eprintln!(
            "GitHub authentication complete; signer session is valid for {} seconds and was cached locally.",
            session.expires_in
        );
    } else {
        eprintln!(
            "GitHub authentication complete; signer session is valid for {} seconds.",
            session.expires_in
        );
    }
    Ok(Zeroizing::new(session.access_token))
}

async fn github_oauth_http_request(
    client: &reqwest::Client,
    request: oauth2::HttpRequest,
) -> std::result::Result<oauth2::HttpResponse, oauth2::HttpClientError<reqwest::Error>> {
    let mut response = oauth2::AsyncHttpClient::call(client, request).await?;
    normalize_github_oauth_error_response(&mut response);
    Ok(response)
}

fn normalize_github_oauth_error_response(response: &mut oauth2::HttpResponse) {
    // GitHub's OAuth endpoints may return a JSON OAuth error with HTTP 200. oauth2
    // intentionally decides success/error from the HTTP status, so normalize that
    // GitHub-specific behavior before the crate parses the response.
    if response.status() != reqwest::StatusCode::OK {
        return;
    }

    let has_oauth_error = serde_json::from_slice::<serde_json::Value>(response.body())
        .is_ok_and(|body| body.get("error").is_some_and(serde_json::Value::is_string));
    if has_oauth_error {
        *response.status_mut() = reqwest::StatusCode::BAD_REQUEST;
    }
}

fn https_oauth_url(value: &str, purpose: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(value)
        .with_context(|| format!("signer returned an invalid GitHub {purpose} URL"))?;
    if url.scheme() != "https" || url.cannot_be_a_base() {
        bail!("signer returned a GitHub {purpose} URL that is not hierarchical HTTPS");
    }
    Ok(url)
}

async fn response_error(response: reqwest::Response, action: &str) -> anyhow::Error {
    let status = response.status();
    match response.bytes().await {
        Ok(body) => match serde_json::from_slice::<ErrorBody>(&body) {
            Ok(problem) => anyhow::anyhow!(
                "{action} failed: {} (request {})",
                problem.error,
                problem.request_id
            ),
            Err(_) => anyhow::anyhow!("{action} failed with HTTP status {status}"),
        },
        Err(error) => anyhow::anyhow!("{action} failed with HTTP status {status}: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_GITHUB_ACTIONS_AUDIENCE, GithubActionsOidcResponse, github_actions_request_url,
        https_oauth_url, normalize_github_oauth_error_response, should_use_github_actions,
    };

    #[test]
    fn oidc_default_audience_matches_server_default() {
        assert_eq!(DEFAULT_GITHUB_ACTIONS_AUDIENCE, "microtun-signer");
    }

    #[test]
    fn oidc_request_url_preserves_existing_query_and_encodes_audience() {
        let url = github_actions_request_url(
            "https://pipelines.actions.githubusercontent.com/abc?api-version=2.0&other=1",
            "https://signer.example/a?b=c&d=e",
        )
        .unwrap();
        let params: Vec<_> = url.query_pairs().collect();
        assert_eq!(params.len(), 3);
        assert_eq!(params[0].0, "api-version");
        assert_eq!(params[0].1, "2.0");
        assert_eq!(params[1].0, "other");
        assert_eq!(params[1].1, "1");
        assert_eq!(params[2].0, "audience");
        assert_eq!(params[2].1, "https://signer.example/a?b=c&d=e");
    }

    #[test]
    fn oidc_request_rejects_unsafe_urls_and_invalid_audiences() {
        for url in [
            "http://pipelines.actions.githubusercontent.com/abc",
            "file:///tmp/token",
            "https://user:password@pipelines.actions.githubusercontent.com/abc",
            "https://pipelines.actions.githubusercontent.com/abc#fragment",
            "https://pipelines.actions.githubusercontent.com/abc?audience=wrong",
            "not a url",
        ] {
            assert!(github_actions_request_url(url, "microtun-signer").is_err());
        }
        assert!(github_actions_request_url("https://example.com/", "  ").is_err());
    }

    #[test]
    fn oidc_response_uses_githubs_value_field() {
        let response: GithubActionsOidcResponse =
            serde_json::from_str(r#"{"value":"header.payload.signature"}"#).unwrap();
        assert_eq!(response.value, "header.payload.signature");
        assert!(serde_json::from_str::<GithubActionsOidcResponse>(r#"{"token":"wrong"}"#).is_err());
    }

    #[test]
    fn oidc_selection_respects_explicit_authentication() {
        assert!(should_use_github_actions(true, false, true, false));
        assert!(should_use_github_actions(false, false, false, true));
        assert!(!should_use_github_actions(false, false, true, true));
        assert!(!should_use_github_actions(false, true, false, true));
        assert!(!should_use_github_actions(false, false, false, false));
    }

    #[test]
    fn oauth_endpoint_must_be_hierarchical_https() {
        let url = https_oauth_url("https://github.com/login/device/code", "device-code").unwrap();
        assert_eq!(url.scheme(), "https");

        assert!(https_oauth_url("http://github.com/login/device/code", "device-code").is_err());
        assert!(https_oauth_url("mailto:oauth@example.com", "device-code").is_err());
    }

    #[test]
    fn github_oauth_200_error_is_normalized_for_oauth2() {
        let mut response =
            oauth2::HttpResponse::new(br#"{"error":"authorization_pending"}"#.to_vec());
        *response.status_mut() = reqwest::StatusCode::OK;

        normalize_github_oauth_error_response(&mut response);

        assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn github_oauth_200_success_is_not_normalized() {
        let mut response = oauth2::HttpResponse::new(
            br#"{"access_token":"token","token_type":"bearer"}"#.to_vec(),
        );
        *response.status_mut() = reqwest::StatusCode::OK;

        normalize_github_oauth_error_response(&mut response);

        assert_eq!(response.status(), reqwest::StatusCode::OK);
    }
}
