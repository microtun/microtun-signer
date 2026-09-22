use std::time::Duration;

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
    #[arg(long = "github-login")]
    github_login: bool,

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

    let (mut token, reused_cached_session) = if args.github_login {
        let cached = match session_cache::load(&base_url) {
            Ok(cached) => cached,
            Err(error) => {
                eprintln!("Warning: could not read signer session cache: {error:#}");
                None
            }
        };
        match cached {
            Some(token) => {
                eprintln!("Reusing cached signer session.");
                (token, true)
            }
            None => (github_device_login(&client, &base_url).await?, false),
        }
    } else if let Some(token) = args.token {
        if token.is_empty() {
            bail!("--token must not be empty");
        }
        (Zeroizing::new(token), false)
    } else {
        bail!(
            "no bearer credential was provided; set MICROTUN_SIGNER_TOKEN/--token, or pass --github-login for GitHub user authentication"
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
    if signature.len() != 64 {
        bail!("signing API returned a signature with an invalid length");
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
    use super::{https_oauth_url, normalize_github_oauth_error_response};

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
