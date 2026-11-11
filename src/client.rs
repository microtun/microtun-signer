use std::{collections::HashMap, env, net::Ipv4Addr, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use axum::{
    Router,
    extract::{Query, State},
    http::StatusCode,
    routing::get,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use clap::Args;
use oauth2::basic::{BasicClient, BasicErrorResponse, BasicErrorResponseType, BasicTokenResponse};
use oauth2::{
    AuthType, AuthUrl, AuthorizationCode, ClientId, CsrfToken, EndpointNotSet, EndpointSet,
    PkceCodeChallenge, RedirectUrl, RefreshToken, RequestTokenError, TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

use crate::{
    oauth::{CLI_CLIENT_ID, verification_code},
    session_cache::{CachedSession, SessionCache, Stored},
    valid_key_id,
};

#[derive(Debug, Args)]
pub struct SignArgs {
    /// Immutable signing key ID to use.
    #[arg(short = 'k', long = "key-id", env = "MICROTUN_SIGNER_KEY_ID")]
    pub(crate) key_id: String,

    /// Bearer credential accepted by the signer. Prefer MICROTUN_SIGNER_TOKEN
    /// over --token so the credential is not exposed in the process list.
    #[arg(long, env = "MICROTUN_SIGNER_TOKEN", hide_env_values = true)]
    token: Option<String>,

    /// Authenticate as a GitHub user, reusing (and silently refreshing) a
    /// cached signer session when available. If a new login is required, a
    /// browser on this machine is sent through GitHub sign-in.
    /// This takes precedence over MICROTUN_SIGNER_TOKEN/--token.
    #[arg(long = "github-login", env = "MICROTUN_SIGNER_GITHUB_LOGIN")]
    github_login: bool,

    /// With --github-login, only print the sign-in URL instead of also trying
    /// to open it in the default browser.
    #[arg(long = "no-browser", env = "MICROTUN_SIGNER_NO_BROWSER")]
    no_browser: bool,

    /// Request a fresh GitHub Actions OIDC token for this signing operation.
    /// Requires a workflow/job with `id-token: write` permission and takes
    /// precedence over MICROTUN_SIGNER_TOKEN/--token.
    #[arg(long = "github-actions", env = "MICROTUN_SIGNER_GITHUB_ACTIONS")]
    github_actions: bool,

    /// OIDC audience, matching the signer's GitHubActions.Audience setting.
    /// Defaults to "microtun-signer"; only valid when using GitHub Actions OIDC
    /// (explicitly or by automatic detection inside a GitHub Actions job).
    #[arg(long, env = "MICROTUN_SIGNER_AUDIENCE")]
    audience: Option<String>,

    /// 32-byte SHA-256 firmware digest encoded as base64.
    #[arg(short = 'd', long, env = "MICROTUN_SIGNER_DIGEST")]
    pub(crate) digest: String,
}

#[derive(Debug, Args)]
pub struct PublicKeyArgs {
    /// Immutable signing key ID to fetch.
    #[arg(short = 'k', long = "key-id", env = "MICROTUN_SIGNER_KEY_ID")]
    pub(crate) key_id: String,
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

/// How long the CLI waits for the user to get through GitHub in the browser.
/// The signer forgets an unfinished sign-in after ten minutes.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const CALLBACK_PATH: &str = "/callback";

#[derive(Deserialize)]
struct ErrorBody {
    error: String,
    request_id: String,
}

pub async fn sign(url: &str, args: SignArgs) -> Result<()> {
    validate_key_id(&args.key_id)?;

    // Check parsed boolean values rather than clap argument presence, so an
    // environment setting of `false` does not conflict with the other mode.
    if args.github_login && args.github_actions {
        bail!("--github-login and --github-actions are mutually exclusive");
    }

    // An audience is useful both for explicit --github-actions and for the
    // automatic OIDC flow inside GitHub Actions. Reject it for other auth modes
    // rather than silently ignoring an explicit flag or environment setting.
    let use_actions = should_use_github_actions(
        args.github_actions,
        args.github_login,
        args.token.is_some(),
        env::var_os("ACTIONS_ID_TOKEN_REQUEST_URL").is_some(),
    );
    if let Some(audience) = args.audience.as_deref() {
        if !use_actions {
            bail!(
                "--audience/MICROTUN_SIGNER_AUDIENCE requires GitHub Actions authentication (--github-actions or automatic runner OIDC)"
            );
        }
        if audience.trim().is_empty() {
            bail!("--audience/MICROTUN_SIGNER_AUDIENCE must not be empty");
        }
    }

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
    let session_cache = SessionCache::for_signer(&base_url);
    let open_browser: fn(&reqwest::Url) = if args.no_browser {
        |_| {}
    } else {
        open_in_browser
    };

    // GitHub injects these variables only into jobs with OIDC permission. Prefer
    // an explicitly selected authentication method when one was provided.
    let (mut token, reused_cached_session) = if args.github_login {
        github_user_session(&client, &base_url, &session_cache, None, open_browser).await?
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
        // Most likely the signer restarted, which ends every session.
        eprintln!("Cached signer session is no longer accepted; renewing it.");
        let rejected = token.clone();
        (token, _) = github_user_session(
            &client,
            &base_url,
            &session_cache,
            Some(&rejected),
            open_browser,
        )
        .await?;
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
        bail!(
            "ACTIONS_ID_TOKEN_REQUEST_URL must be a hierarchical HTTPS URL without credentials or a fragment"
        );
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

/// Tokens the signer issued for one GitHub login.
struct Session {
    access_token: Zeroizing<String>,
    expires_in: u64,
    refresh_token: Option<Zeroizing<String>>,
}

/// The signer is the OAuth 2.0 authorization server for this CLI. It sends
/// the browser on to GitHub itself; no GitHub credential ever reaches the CLI.
type SignerOAuthClient =
    BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;

fn signer_oauth_client(signer_base_url: &reqwest::Url) -> Result<SignerOAuthClient> {
    let endpoint = |path: &str| {
        signer_base_url
            .join(path)
            .context("failed to construct signer OAuth endpoint URL")
    };
    // A public client: it has no secret and identifies itself in the body.
    Ok(BasicClient::new(ClientId::new(CLI_CLIENT_ID.to_owned()))
        .set_auth_uri(AuthUrl::from_url(endpoint("v1/auth/authorize")?))
        .set_token_uri(TokenUrl::from_url(endpoint("v1/auth/token")?))
        .set_auth_type(AuthType::RequestBody))
}

fn session_from_token_response(token: &BasicTokenResponse) -> Result<Session> {
    let access_token = Zeroizing::new(token.access_token().secret().to_owned());
    let expires_in = token.expires_in().map_or(0, |ttl| ttl.as_secs());
    if access_token.is_empty() || expires_in == 0 {
        bail!("signer returned an invalid OAuth token response");
    }
    Ok(Session {
        access_token,
        expires_in,
        refresh_token: token
            .refresh_token()
            .map(|token| Zeroizing::new(token.secret().to_owned())),
    })
}

fn token_request_error<E: std::error::Error + Send + Sync + 'static>(
    action: &str,
    error: RequestTokenError<E, BasicErrorResponse>,
) -> anyhow::Error {
    match error {
        RequestTokenError::ServerResponse(response) => match response.error_description() {
            Some(description) => {
                anyhow::anyhow!("{action} failed: {} ({description})", response.error())
            }
            None => anyhow::anyhow!("{action} failed: {}", response.error()),
        },
        other => anyhow::Error::new(other).context(format!("{action} failed")),
    }
}

fn load_cached_session(cache: &SessionCache) -> Option<CachedSession> {
    match cache.load() {
        Ok(cached) => cached,
        Err(error) => {
            eprintln!("Warning: could not read signer session cache: {error:#}");
            None
        }
    }
}

/// Produce an access token for a GitHub user, doing as little as possible:
/// the cached access token, else a silent refresh, else a browser sign-in.
///
/// `rejected` is an unexpired cached access token the signer just refused
/// (typically because the service restarted); it is never returned again.
/// The boolean reports whether the token came straight from the cache.
async fn github_user_session(
    client: &reqwest::Client,
    signer_base_url: &reqwest::Url,
    cache: &SessionCache,
    rejected: Option<&str>,
    open_browser: fn(&reqwest::Url),
) -> Result<(Zeroizing<String>, bool)> {
    let usable = |cached: &Option<CachedSession>| {
        cached
            .as_ref()
            .and_then(|cached| cached.access_token.clone())
            .filter(|token| Some(token.as_str()) != rejected)
    };
    if let Some(token) = usable(&load_cached_session(cache)) {
        return Ok((token, true));
    }

    // Renew under a lock, then look again: another invocation may have
    // renewed the session while this one was waiting.
    let lock_cache = cache.clone();
    let _lock = match tokio::task::spawn_blocking(move || lock_cache.lock()).await {
        Ok(Ok(lock)) => lock,
        Ok(Err(error)) => {
            eprintln!("Warning: could not lock signer session cache: {error:#}");
            None
        }
        Err(_) => None,
    };
    let cached = load_cached_session(cache);
    if let Some(token) = usable(&cached) {
        return Ok((token, true));
    }

    let mut session = None;
    if let Some(refresh_token) = cached.and_then(|cached| cached.refresh_token) {
        session = refresh_session(client, signer_base_url, &refresh_token).await?;
    }
    let session = match session {
        Some(session) => session,
        None => {
            if let Err(error) = cache.remove() {
                eprintln!("Warning: could not remove stale signer session cache: {error:#}");
            }
            let session = github_browser_login(client, signer_base_url, open_browser).await?;
            eprintln!("GitHub sign-in complete.");
            session
        }
    };

    match cache.store(
        &session.access_token,
        session.expires_in,
        session.refresh_token.as_ref().map(|token| token.as_str()),
    ) {
        Ok(Stored::Nowhere) => {
            eprintln!("Warning: nowhere to cache the signer session; the next run signs in again.");
        }
        Ok(Stored::Keyring | Stored::File) => {}
        Err(error) => eprintln!("Warning: could not cache signer session: {error:#}"),
    }
    Ok((session.access_token, false))
}

/// Trade a refresh token for a new access token and a new (rotated) refresh
/// token. `Ok(None)` means the signer no longer honours the refresh token and
/// the user has to sign in again.
async fn refresh_session(
    client: &reqwest::Client,
    signer_base_url: &reqwest::Url,
    refresh_token: &str,
) -> Result<Option<Session>> {
    let outcome = signer_oauth_client(signer_base_url)?
        .exchange_refresh_token(&RefreshToken::new(refresh_token.to_owned()))
        .request_async(client)
        .await;
    match outcome {
        Ok(token) => session_from_token_response(&token).map(Some),
        Err(RequestTokenError::ServerResponse(response))
            if *response.error() == BasicErrorResponseType::InvalidGrant =>
        {
            Ok(None)
        }
        Err(error) => Err(token_request_error("signer session refresh", error)),
    }
}

/// OAuth 2.0 authorization code flow with PKCE for native apps (RFC 8252):
/// listen on a loopback port, send the user's browser to the signer (which
/// sends it on to GitHub), receive the authorization code on the loopback
/// redirect, and redeem it together with the PKCE verifier.
async fn github_browser_login(
    client: &reqwest::Client,
    signer_base_url: &reqwest::Url,
    open_browser: impl FnOnce(&reqwest::Url),
) -> Result<Session> {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .context("failed to listen on a loopback port for the sign-in redirect")?;
    let port = listener
        .local_addr()
        .context("failed to inspect the loopback sign-in listener")?
        .port();
    let redirect_uri = RedirectUrl::new(format!("http://127.0.0.1:{port}{CALLBACK_PATH}"))
        .context("failed to construct loopback redirect URI")?;
    let oauth = signer_oauth_client(signer_base_url)?.set_redirect_uri(redirect_uri);

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    // The signer's confirmation page derives the same code from the challenge.
    let verification_code = verification_code(pkce_challenge.as_str());
    let (authorize_url, state) = oauth
        .authorize_url(CsrfToken::new_random)
        .set_pkce_challenge(pkce_challenge)
        .url();

    eprintln!("GitHub sign-in required. Open this URL in a browser on this machine:");
    eprintln!();
    eprintln!("  {authorize_url}");
    eprintln!();
    eprintln!("The page shows a verification code. Continue there only if it is:");
    eprintln!();
    eprintln!("  {verification_code}");
    eprintln!();
    eprintln!("Waiting for the sign-in to complete...");
    open_browser(&authorize_url);

    let code = wait_for_authorization_code(listener, state.secret()).await?;
    let token = oauth
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(pkce_verifier)
        .request_async(client)
        .await
        .map_err(|error| token_request_error("signer token exchange", error))?;
    session_from_token_response(&token)
}

#[derive(Clone)]
struct CallbackState {
    expected_state: Arc<str>,
    outcome: mpsc::Sender<std::result::Result<String, String>>,
}

/// Serve the loopback redirect URI until the browser delivers the outcome of
/// the sign-in, or the user runs out of time.
async fn wait_for_authorization_code(
    listener: tokio::net::TcpListener,
    expected_state: &str,
) -> Result<String> {
    let (outcome_tx, mut outcome_rx) = mpsc::channel(1);
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let app = Router::new()
        .route(CALLBACK_PATH, get(loopback_callback))
        .with_state(CallbackState {
            expected_state: expected_state.into(),
            outcome: outcome_tx,
        });
    let server = tokio::spawn(
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .into_future(),
    );

    let outcome = tokio::time::timeout(LOGIN_TIMEOUT, outcome_rx.recv()).await;
    // Let the browser receive its answer before the listener goes away.
    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;

    match outcome {
        Ok(Some(Ok(code))) => Ok(code),
        Ok(Some(Err(reason))) => bail!("GitHub sign-in failed: {reason}"),
        Ok(None) => bail!("the loopback sign-in listener stopped unexpectedly"),
        Err(_) => bail!(
            "timed out after {} seconds waiting for the GitHub sign-in to complete",
            LOGIN_TIMEOUT.as_secs()
        ),
    }
}

/// Responses are plain text on purpose: `error_description` comes from the
/// query string and must not be rendered as HTML.
async fn loopback_callback(
    State(state): State<CallbackState>,
    Query(params): Query<HashMap<String, String>>,
) -> (StatusCode, &'static str) {
    // Anything on this machine (including a web page) can reach a loopback
    // port. Requests that do not carry this login's state are ignored and do
    // not end the wait.
    if params.get("state").map(String::as_str) != Some(&*state.expected_state) {
        return (
            StatusCode::BAD_REQUEST,
            "This request does not belong to the sign-in in progress.\n",
        );
    }
    let (outcome, status, page) = match (params.get("code"), params.get("error")) {
        (Some(code), None) if !code.is_empty() => (
            Ok(code.clone()),
            StatusCode::OK,
            "Signed in to microtun-signer. You can close this tab and return to the terminal.\n",
        ),
        (_, error) => (
            Err(params
                .get("error_description")
                .or(error)
                .cloned()
                .unwrap_or_else(|| "the signer returned no authorization code".to_owned())),
            StatusCode::FORBIDDEN,
            "Sign-in to microtun-signer failed. Return to the terminal for details.\n",
        ),
    };
    let _ = state.outcome.try_send(outcome);
    (status, page)
}

/// Best effort. The URL is always printed as well, and it carries no secret:
/// only the state and the PKCE challenge.
fn open_in_browser(url: &reqwest::Url) {
    // Without a graphical session the only browsers left are terminal ones,
    // which would take over the terminal this command is waiting in.
    let headless_linux = cfg!(all(unix, not(target_os = "macos")))
        && ["DISPLAY", "WAYLAND_DISPLAY", "WSL_DISTRO_NAME"]
            .iter()
            .all(|name| env::var_os(name).is_none());
    if headless_linux {
        return;
    }
    let url = url.to_string();
    // Opening can block until the browser process returns; never hold up the
    // loopback listener for it.
    std::thread::spawn(move || {
        let _ = webbrowser::open_browser_with_options(
            webbrowser::Browser::Default,
            &url,
            webbrowser::BrowserOptions::new().with_suppress_output(true),
        );
    });
}

/// RFC 7009 revocation: ends the login the token belongs to on the signer.
async fn revoke_token(
    client: &reqwest::Client,
    signer_base_url: &reqwest::Url,
    token: &str,
) -> Result<()> {
    let endpoint = signer_base_url
        .join("v1/auth/revoke")
        .context("failed to construct signer revocation URL")?;
    let response = client
        .post(endpoint)
        .form(&[("token", token), ("client_id", CLI_CLIENT_ID)])
        .send()
        .await
        .context("failed to call signer revocation API")?;
    if !response.status().is_success() {
        return Err(response_error(response, "session revocation").await);
    }
    Ok(())
}

pub async fn logout(url: &str) -> Result<()> {
    let base_url = signer_base_url(url)?;
    let cache = SessionCache::for_signer(&base_url);
    let cached = cache
        .load()
        .context("failed to read signer session cache")?;
    // Forget the session locally first, so it is gone even if the signer
    // cannot be reached.
    cache.remove()?;
    let Some(token) = cached.and_then(|cached| cached.refresh_token.or(cached.access_token)) else {
        eprintln!("No cached signer session for {base_url}.");
        return Ok(());
    };
    revoke_token(&public_api_client()?, &base_url, &token)
        .await
        .context("the cached session was removed locally, but the signer could not revoke it")?;
    eprintln!("Signed out of {base_url}.");
    Ok(())
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
        should_use_github_actions,
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

    mod login {
        use std::{net::SocketAddr, sync::Arc};

        use axum::http::{HeaderMap, StatusCode, header::AUTHORIZATION};

        use super::super::{
            github_browser_login, github_user_session, public_api_client, refresh_session,
            revoke_token, signer_base_url,
        };
        use crate::{
            api::AppState,
            auth::Authenticator,
            authorization::Authorizer,
            config::IdentityConfig,
            key::KeyStore,
            oauth::verification_code,
            session_cache::SessionCache,
            test_github::{
                MockGithub, browser_client, browser_sign_in, follow_redirects,
                open_confirmation_page, submit_confirmation,
            },
        };

        struct Signer {
            base_url: reqwest::Url,
            auth: Authenticator,
            github: MockGithub,
            tasks: Vec<tokio::task::JoinHandle<()>>,
        }

        impl Drop for Signer {
            fn drop(&mut self) {
                for task in &self.tasks {
                    task.abort();
                }
            }
        }

        /// A real signer router on a loopback port, backed by a mock GitHub.
        async fn spawn_signer(github: MockGithub) -> Signer {
            let (github_url, github_task) = github.clone().spawn().await;
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let public_url = format!("http://{}", listener.local_addr().unwrap());
            let identity: IdentityConfig = toml::from_str(
                "ID = \"maintainer\"\nType = \"github-account\"\nGitHubUserID = \"42\"\n",
            )
            .unwrap();
            let auth =
                Authenticator::for_tests_with_github(&github_url, &public_url, vec![identity]);
            let state = AppState::new(
                Arc::new(KeyStore::from_keys_for_tests(vec![
                    crate::key::KeyMaterial::from_pem_with_algorithm_for_tests(
                        "prod",
                        crate::config::KeyAlgorithm::P256,
                        include_str!("../tests/fixtures/test-p256-scrypt.pem"),
                    ),
                ])),
                auth.clone(),
                Authorizer::new(Vec::new()),
            );
            let app = crate::public_router(state, None);
            let signer_task = tokio::spawn(async move {
                axum::serve(
                    listener,
                    app.into_make_service_with_connect_info::<SocketAddr>(),
                )
                .await
                .unwrap();
            });
            Signer {
                base_url: signer_base_url(&public_url).unwrap(),
                auth,
                github,
                tasks: vec![github_task, signer_task],
            }
        }

        /// Stands in for the user at their browser: confirms on the signer's
        /// page and follows signer -> GitHub -> signer -> CLI loopback
        /// listener.
        fn browser(url: &reqwest::Url) {
            let url = url.clone();
            tokio::spawn(async move {
                let page = browser_sign_in(&url).await;
                assert_eq!(page.url().host_str(), Some("127.0.0.1"));
                assert_eq!(page.url().path(), "/callback");
            });
        }

        /// A well-formed authorization URL, as the CLI (or anyone) builds it.
        fn authorize_url(signer: &Signer, redirect_uri: &str, client_id: &str) -> reqwest::Url {
            let mut url = signer.base_url.join("v1/auth/authorize").unwrap();
            url.query_pairs_mut()
                .append_pair("response_type", "code")
                .append_pair("client_id", client_id)
                .append_pair("redirect_uri", redirect_uri)
                .append_pair("state", "s")
                .append_pair("code_challenge", CHALLENGE)
                .append_pair("code_challenge_method", "S256");
            url
        }

        const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        const LOOPBACK: &str = "http://127.0.0.1:4000/callback";

        fn origin(signer: &Signer) -> String {
            signer.base_url.origin().ascii_serialization()
        }

        async fn accepted(auth: &Authenticator, access_token: &str) -> bool {
            let mut headers = HeaderMap::new();
            headers.insert(
                AUTHORIZATION,
                format!("Bearer {access_token}").parse().unwrap(),
            );
            auth.authenticate(&headers).await.is_ok()
        }

        #[tokio::test]
        async fn browser_login_refresh_and_logout_round_trip() {
            let signer = spawn_signer(MockGithub::default()).await;
            let client = public_api_client().unwrap();

            let session = github_browser_login(&client, &signer.base_url, browser)
                .await
                .unwrap();
            assert!(session.access_token.starts_with("mts_"));
            assert_eq!(session.expires_in, 900);
            let refresh_token = session.refresh_token.unwrap();
            assert!(refresh_token.starts_with("mtr_"));
            assert!(accepted(&signer.auth, &session.access_token).await);
            // GitHub was asked exactly once and its token did not outlive it.
            assert_eq!(signer.github.exchanges(), 1);
            assert_eq!(signer.github.revocations(), 1);

            let refreshed = refresh_session(&client, &signer.base_url, &refresh_token)
                .await
                .unwrap()
                .expect("refresh token is honoured");
            assert_ne!(*refreshed.access_token, *session.access_token);
            assert!(accepted(&signer.auth, &refreshed.access_token).await);
            assert!(accepted(&signer.auth, &session.access_token).await);
            assert_eq!(signer.github.exchanges(), 1);

            revoke_token(
                &client,
                &signer.base_url,
                refreshed.refresh_token.as_deref().unwrap(),
            )
            .await
            .unwrap();
            assert!(!accepted(&signer.auth, &refreshed.access_token).await);
            assert!(!accepted(&signer.auth, &session.access_token).await);
        }

        /// A private, empty cache directory that is removed again on drop.
        struct CacheDir(std::path::PathBuf);

        impl CacheDir {
            fn new(name: &str) -> Self {
                let path = std::env::temp_dir().join(format!(
                    "microtun-signer-test-{}-{name}",
                    std::process::id()
                ));
                let _ = std::fs::remove_dir_all(&path);
                Self(path)
            }

            /// Make the cached access token look expired, as time would.
            fn expire_access_token(&self) {
                for entry in std::fs::read_dir(&self.0).unwrap() {
                    let path = entry.unwrap().path();
                    if path
                        .extension()
                        .is_some_and(|extension| extension == "json")
                    {
                        let mut stored: serde_json::Value =
                            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                        stored["expires_at"] = 0.into();
                        std::fs::write(&path, stored.to_string()).unwrap();
                    }
                }
            }
        }

        impl Drop for CacheDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        fn no_browser(_: &reqwest::Url) {
            panic!("a browser sign-in was not expected here");
        }

        #[tokio::test]
        async fn cached_session_is_reused_then_refreshed_then_renewed() {
            let signer = spawn_signer(MockGithub::default()).await;
            let client = public_api_client().unwrap();
            let dir = CacheDir::new("lifecycle");
            let cache = SessionCache::in_dir(&dir.0, &signer.base_url);

            // Nothing cached: sign in through the browser.
            let (first, from_cache) =
                github_user_session(&client, &signer.base_url, &cache, None, browser)
                    .await
                    .unwrap();
            assert!(!from_cache);
            assert_eq!(signer.github.exchanges(), 1);

            // Still fresh: no network, no browser.
            let (again, from_cache) =
                github_user_session(&client, &signer.base_url, &cache, None, no_browser)
                    .await
                    .unwrap();
            assert!(from_cache);
            assert_eq!(*again, *first);

            // Access token expired: silently refreshed, GitHub not involved.
            dir.expire_access_token();
            let (refreshed, from_cache) =
                github_user_session(&client, &signer.base_url, &cache, None, no_browser)
                    .await
                    .unwrap();
            assert!(!from_cache);
            assert_ne!(*refreshed, *first);
            assert!(accepted(&signer.auth, &refreshed).await);
            assert_eq!(signer.github.exchanges(), 1);

            // The refreshed pair was written back and is what gets reused.
            let (again, from_cache) =
                github_user_session(&client, &signer.base_url, &cache, None, no_browser)
                    .await
                    .unwrap();
            assert!(from_cache);
            assert_eq!(*again, *refreshed);

            // The signer forgot the login (as a restart would make it): the
            // rejected token is not offered again, the refresh token no
            // longer works either, so the browser is needed once more.
            assert!(signer.auth.revoke_session(&refreshed).is_some());
            let (renewed, from_cache) =
                github_user_session(&client, &signer.base_url, &cache, Some(&refreshed), browser)
                    .await
                    .unwrap();
            assert!(!from_cache);
            assert!(accepted(&signer.auth, &renewed).await);
            assert_eq!(signer.github.exchanges(), 2);
        }

        #[tokio::test]
        async fn concurrent_invocations_share_one_refresh() {
            let signer = spawn_signer(MockGithub::default()).await;
            let client = public_api_client().unwrap();
            let dir = CacheDir::new("concurrent");
            let cache = SessionCache::in_dir(&dir.0, &signer.base_url);
            github_user_session(&client, &signer.base_url, &cache, None, browser)
                .await
                .unwrap();
            dir.expire_access_token();

            // Without the renewal lock both would present the same single-use
            // refresh token and the signer would revoke the login as stolen.
            let renew = || github_user_session(&client, &signer.base_url, &cache, None, no_browser);
            let (a, b, c) = tokio::join!(renew(), renew(), renew());
            let (a, b, c) = (a.unwrap().0, b.unwrap().0, c.unwrap().0);
            assert_eq!(*a, *b);
            assert_eq!(*b, *c);
            assert!(accepted(&signer.auth, &a).await);
        }

        #[tokio::test]
        async fn replayed_refresh_token_requires_a_new_login() {
            let signer = spawn_signer(MockGithub::default()).await;
            let client = public_api_client().unwrap();
            let session = github_browser_login(&client, &signer.base_url, browser)
                .await
                .unwrap();
            let refresh_token = session.refresh_token.unwrap();
            let refreshed = refresh_session(&client, &signer.base_url, &refresh_token)
                .await
                .unwrap()
                .unwrap();

            // invalid_grant surfaces as "sign in again", not as an error.
            assert!(
                refresh_session(&client, &signer.base_url, &refresh_token)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(!accepted(&signer.auth, &refreshed.access_token).await);
            assert!(
                refresh_session(&client, &signer.base_url, "mtr_never-issued")
                    .await
                    .unwrap()
                    .is_none()
            );
        }

        #[tokio::test]
        async fn login_reports_why_the_signer_refused() {
            for (github, expected) in [
                (
                    MockGithub {
                        user_approves: false,
                        ..MockGithub::default()
                    },
                    "cancelled or denied",
                ),
                (
                    MockGithub {
                        user_id: 7,
                        ..MockGithub::default()
                    },
                    "not a configured signer identity",
                ),
                (
                    MockGithub {
                        two_factor_authentication: Some(false),
                        ..MockGithub::default()
                    },
                    "two-factor authentication",
                ),
            ] {
                let signer = spawn_signer(github).await;
                let client = public_api_client().unwrap();
                let error = github_browser_login(&client, &signer.base_url, browser)
                    .await
                    .err()
                    .expect("login must fail")
                    .to_string();
                assert!(error.contains(expected), "{error}");
            }
        }

        #[tokio::test]
        async fn login_endpoints_are_rate_limited_per_client() {
            let signer = spawn_signer(MockGithub::default()).await;
            let client = public_api_client().unwrap();
            let callback = signer.base_url.join("v1/auth/github/callback").unwrap();

            let mut limited = None;
            for _ in 0..40 {
                let response = client.get(callback.clone()).send().await.unwrap();
                if response.status() == StatusCode::TOO_MANY_REQUESTS {
                    limited = Some(response);
                    break;
                }
                assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            }
            let limited = limited.expect("the burst allowance runs out");
            assert!(limited.headers().contains_key("retry-after"));
            let body: serde_json::Value = limited.json().await.unwrap();
            assert_eq!(body["error"], "oauth-login-rate-limited");

            // Only the browser-facing login routes are limited.
            let version = signer.base_url.join("version").unwrap();
            let response = client.get(version).send().await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let token = signer.base_url.join("v1/auth/token").unwrap();
            let response = client.post(token).send().await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn token_endpoint_speaks_rfc_6749_errors() {
            let signer = spawn_signer(MockGithub::default()).await;
            let client = public_api_client().unwrap();
            let endpoint = signer.base_url.join("v1/auth/token").unwrap();
            for (form, expected) in [
                (vec![("grant_type", "password")], "invalid_client"),
                (
                    vec![
                        ("grant_type", "password"),
                        ("client_id", "microtun-signer-cli"),
                    ],
                    "unsupported_grant_type",
                ),
                (
                    vec![
                        ("grant_type", "authorization_code"),
                        ("client_id", "microtun-signer-cli"),
                    ],
                    "invalid_request",
                ),
                (
                    vec![
                        ("grant_type", "authorization_code"),
                        ("client_id", "microtun-signer-cli"),
                        ("code", "mtc_forged"),
                        ("redirect_uri", "http://127.0.0.1:1/callback"),
                        (
                            "code_verifier",
                            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                        ),
                    ],
                    "invalid_grant",
                ),
            ] {
                let response = client
                    .post(endpoint.clone())
                    .form(&form)
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::BAD_REQUEST);
                assert_eq!(response.headers()["cache-control"], "no-store");
                let body: serde_json::Value = response.json().await.unwrap();
                assert_eq!(body["error"], expected);
            }
        }

        #[tokio::test]
        async fn authorize_endpoint_shows_a_confirmation_page_and_starts_nothing() {
            let signer = spawn_signer(MockGithub::default()).await;
            let client = public_api_client().unwrap();

            let response = client
                .get(authorize_url(&signer, LOOPBACK, "microtun-signer-cli"))
                .send()
                .await
                .unwrap();
            // No redirect: GitHub is not involved until the person confirms.
            assert_eq!(response.status(), StatusCode::OK);
            let headers = response.headers().clone();
            assert!(headers.get("location").is_none());
            assert!(
                headers["content-type"]
                    .to_str()
                    .unwrap()
                    .starts_with("text/html")
            );
            assert_eq!(headers["cache-control"], "no-store");
            assert_eq!(headers["x-frame-options"], "DENY");
            // `no-referrer` would make browsers submit the form as Origin: null.
            assert_eq!(headers["referrer-policy"], "same-origin");
            let csp = headers["content-security-policy"].to_str().unwrap();
            assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
            let cookie = headers["set-cookie"].to_str().unwrap();
            assert!(cookie.starts_with("mts-login="), "{cookie}");
            assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Lax"));

            let html = response.text().await.unwrap();
            assert!(html.contains(&verification_code(CHALLENGE)), "{html}");
            assert!(html.contains("127.0.0.1:4000"));

            for (redirect_uri, client_id) in [
                ("https://evil.example/callback", "microtun-signer-cli"),
                (LOOPBACK, "someone-else"),
            ] {
                let response = client
                    .get(authorize_url(&signer, redirect_uri, client_id))
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::BAD_REQUEST);
                assert!(response.headers().get("location").is_none());
                assert!(response.headers().get("set-cookie").is_none());
            }

            // A callback nobody started is answered without contacting GitHub.
            let mut callback = signer.base_url.join("v1/auth/github/callback").unwrap();
            callback
                .query_pairs_mut()
                .append_pair("code", "ghcode_x")
                .append_pair("state", "forged");
            let response = client.get(callback).send().await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(signer.github.exchanges(), 0);
        }

        #[tokio::test]
        async fn a_second_tab_keeps_the_browsers_login_cookie() {
            let signer = spawn_signer(MockGithub::default()).await;
            let url = authorize_url(&signer, LOOPBACK, "microtun-signer-cli");
            let first = open_confirmation_page(&url).await;
            let second = browser_client()
                .get(url)
                .header("cookie", &first.cookie)
                .send()
                .await
                .unwrap();
            let reissued = second.headers()["set-cookie"].to_str().unwrap();
            assert!(
                reissued.starts_with(&format!("{};", first.cookie)),
                "{reissued}"
            );
            // So the form in the first tab still works.
            let submitted =
                submit_confirmation(&first, Some(&first.cookie), Some(&origin(&signer))).await;
            assert_eq!(submitted.status(), StatusCode::SEE_OTHER);
        }

        #[tokio::test]
        async fn confirmation_is_only_accepted_from_the_signers_own_page() {
            let signer = spawn_signer(MockGithub::default()).await;
            let url = authorize_url(&signer, LOOPBACK, "microtun-signer-cli");
            let page = open_confirmation_page(&url).await;
            let origin = origin(&signer);
            let other_browser = open_confirmation_page(&url).await;
            assert_ne!(page.cookie, other_browser.cookie);

            for (cookie, request_origin) in [
                // Another site submitting the form in the victim's browser.
                (Some(page.cookie.as_str()), Some("https://evil.example")),
                (Some(page.cookie.as_str()), Some("null")),
                // No Origin header at all: not a browser form submission.
                (Some(page.cookie.as_str()), None),
                // A form that was served to a different browser.
                (None, Some(origin.as_str())),
                (Some(other_browser.cookie.as_str()), Some(origin.as_str())),
                (Some("mts-login=garbage"), Some(origin.as_str())),
            ] {
                let response = submit_confirmation(&page, cookie, request_origin).await;
                assert_eq!(
                    response.status(),
                    StatusCode::FORBIDDEN,
                    "{cookie:?} {request_origin:?}"
                );
                assert!(response.headers().get("location").is_none());
            }

            // The redirect URI is validated again when the form comes back.
            let mut tampered = open_confirmation_page(&url).await;
            for (name, value) in &mut tampered.fields {
                if name == "redirect_uri" {
                    *value = "https://evil.example/callback".into();
                }
            }
            let response =
                submit_confirmation(&tampered, Some(&tampered.cookie), Some(&origin)).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert!(response.headers().get("location").is_none());

            // The real thing goes to GitHub, carrying none of the CLI's values.
            let response = submit_confirmation(&page, Some(&page.cookie), Some(&origin)).await;
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            let location = response.headers()["location"].to_str().unwrap();
            assert!(
                location.contains("/login/oauth/authorize?client_id=Iv1.test"),
                "{location}"
            );
            assert!(!location.contains(CHALLENGE));
            assert_eq!(response.headers()["referrer-policy"], "no-referrer");
        }

        /// The attacker confirms in their own browser and sends the victim
        /// the resulting GitHub link. GitHub does not prompt, so the victim's
        /// browser arrives at the callback with a valid state - but without
        /// the cookie of the browser that confirmed.
        #[tokio::test]
        async fn github_link_prepared_in_another_browser_is_refused() {
            let signer = spawn_signer(MockGithub::default()).await;
            let origin = origin(&signer);
            let url = authorize_url(&signer, LOOPBACK, "microtun-signer-cli");

            for victim_cookie in [
                None,
                Some("mts-login=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            ] {
                let attacker = open_confirmation_page(&url).await;
                let to_github =
                    submit_confirmation(&attacker, Some(&attacker.cookie), Some(&origin)).await;
                assert_eq!(to_github.status(), StatusCode::SEE_OTHER);

                let page = follow_redirects(to_github, &origin, victim_cookie).await;
                assert_eq!(page.status(), StatusCode::FORBIDDEN);
                // It ended at the signer, not at the attacker's loopback port.
                assert_eq!(page.url().path(), "/v1/auth/github/callback");
                assert!(page.headers().get("location").is_none());
                assert!(
                    page.text()
                        .await
                        .unwrap()
                        .contains("not started in this browser")
                );
            }
            // GitHub's code was never exchanged, and no session exists.
            assert_eq!(signer.github.exchanges(), 0);
        }

        /// The attacker sends the victim the signer's own authorization link.
        /// Opening it does nothing by itself any more.
        #[tokio::test]
        async fn opening_a_sign_in_link_without_confirming_starts_no_login() {
            let signer = spawn_signer(MockGithub::default()).await;
            let url = authorize_url(&signer, LOOPBACK, "microtun-signer-cli");
            let response = reqwest::Client::new().get(url).send().await.unwrap();
            // A redirect-following client stays on the signer's page.
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.url().path(), "/v1/auth/authorize");
            assert_eq!(signer.github.exchanges(), 0);
        }
    }
}
