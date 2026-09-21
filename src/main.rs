mod api;
mod auth;
mod authorization;
mod config;
mod key;

use std::{
    fs,
    net::SocketAddr,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use clap::{Parser, Subcommand};
use oauth2::basic::BasicClient;
use oauth2::{
    ClientId, DeviceAuthorizationUrl, Scope, StandardDeviceAuthorizationResponse, TokenResponse,
    TokenUrl,
};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tower_http::{catch_panic::CatchPanicLayer, trace::TraceLayer};
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

use crate::{
    api::{
        AdminState, AppState, create_signature, get_public_key, github_oauth_device_config,
        github_oauth_device_exchange, health, unlock_key,
    },
    auth::Authenticator,
    authorization::Authorizer,
    config::{Config, DEFAULT_ADMIN_SOCKET_PATH},
    key::KeyRing,
};

#[derive(Debug, Parser)]
#[command(name = "microtun-firmware-signer", version)]
struct Cli {
    /// Path to the service TOML configuration
    /// [default: /etc/microtun-firmware-signer/config.toml].
    ///
    /// The unlock subcommand only reads it when given explicitly, so operators
    /// do not need read access to the service configuration.
    #[arg(short = 'c', long, env = "MICROTUN_SIGNER_CONFIG", global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Interactively unlock an active signing key.
    Unlock(UnlockArgs),
    /// Request a signature from a running firmware signer.
    Sign(SignArgs),
}

#[derive(Debug, clap::Args)]
struct AdminSocketArgs {
    /// Unix-domain socket exposed by the signer's local admin API.
    #[arg(short = 's', long, env = "MICROTUN_SIGNER_ADMIN_SOCKET")]
    socket: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
struct UnlockArgs {
    /// Immutable signing key ID to unlock.
    #[arg(short = 'k', long = "key-id")]
    key_id: String,

    #[command(flatten)]
    admin: AdminSocketArgs,
}

#[derive(Debug, clap::Args)]
struct SignArgs {
    /// Immutable signing key ID to use.
    #[arg(short = 'k', long = "key-id")]
    key_id: String,

    /// Base URL of the public firmware signer API.
    #[arg(short = 'u', long, env = "MICROTUN_SIGNER_URL")]
    url: String,

    /// Bearer credential accepted by the signer. Prefer MICROTUN_SIGNER_TOKEN
    /// over --token so the credential is not exposed in the process list.
    #[arg(long, env = "MICROTUN_SIGNER_TOKEN", hide_env_values = true)]
    token: Option<String>,

    /// Authenticate interactively with GitHub's OAuth device flow. This takes
    /// precedence over MICROTUN_SIGNER_TOKEN/--token.
    #[arg(long)]
    github_device: bool,

    /// 32-byte MCUboot SHA-256 digest encoded as base64.
    #[arg(short = 'd', long)]
    digest: String,
}

const DEFAULT_CONFIG_PATH: &str = "/etc/microtun-firmware-signer/config.toml";

#[derive(Serialize)]
struct UnlockRequest<'a> {
    passphrase: &'a str,
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

#[tokio::main]
async fn main() -> Result<()> {
    let Cli { config, command } = Cli::parse();
    match command {
        Some(Commands::Unlock(args)) => unlock(args, config.as_deref()).await,
        Some(Commands::Sign(args)) => sign(args).await,
        None => run_server(config.unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH))).await,
    }
}

async fn run_server(config_path: PathBuf) -> Result<()> {
    init_tracing();
    let config = Config::load(&config_path)?;

    let keys = Arc::new(KeyRing::load(&config.keys)?);
    for key in keys.iter() {
        tracing::info!(
            key_id = key.id(),
            key_state = key.state().as_str(),
            lock_state = "locked",
            "registered encrypted firmware signing key"
        );
    }
    tracing::info!(
        key_count = keys.len(),
        "firmware signing keyring loaded with all keys locked"
    );

    let authenticator = Authenticator::new(
        config.github.clone(),
        config.github_actions.clone(),
        config.identities.clone(),
    )
    .context("failed to initialize GitHub identity authentication client")?;
    let authorizer = Authorizer::new(config.policies.clone());

    let state = AppState::new(keys.clone(), authenticator, authorizer);

    let app = Router::new()
        .route("/healthz", get(health))
        .route(
            "/v1/auth/github/device",
            get(github_oauth_device_config).post(github_oauth_device_exchange),
        )
        .route("/v1/public-key/{key_id}", get(get_public_key))
        .route("/v1/sign/{key_id}", post(create_signature))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(CatchPanicLayer::new())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // The admin API deliberately lives on a separate Unix-domain socket. It
    // must never be added to the public TCP router or reverse-proxied.
    let admin_app = Router::new()
        .route("/v1/unlock/{key_id}", post(unlock_key))
        .layer(DefaultBodyLimit::max(8 * 1024))
        .layer(CatchPanicLayer::new())
        .layer(TraceLayer::new_for_http())
        .with_state(AdminState::new(keys));

    let listener = tokio::net::TcpListener::bind(config.server.listen)
        .await
        .with_context(|| format!("failed to bind {}", config.server.listen))?;
    let admin_socket_gid = config
        .server
        .admin_socket_group
        .as_deref()
        .map(lookup_group_id)
        .transpose()?;
    let admin_listener = bind_admin_socket(
        &config.server.admin_socket_path,
        config.server.admin_socket_mode,
        admin_socket_gid,
    )?;
    let _admin_socket_guard = AdminSocketGuard(config.server.admin_socket_path.clone());

    tracing::info!(
        listen = %config.server.listen,
        "firmware signing service started"
    );
    tracing::info!(
        socket = %config.server.admin_socket_path.display(),
        mode = %format_args!("{:03o}", config.server.admin_socket_mode),
        group = config.server.admin_socket_group.as_deref().unwrap_or(""),
        "local admin API started"
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    });

    let public_server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(wait_for_shutdown(shutdown_rx.clone()));
    let admin_server = axum::serve(admin_listener, admin_app)
        .with_graceful_shutdown(wait_for_shutdown(shutdown_rx));

    tokio::try_join!(public_server, admin_server).context("HTTP server failed")?;
    Ok(())
}

/// Resolve the admin socket for a client subcommand: an explicit --socket,
/// else the socket named in an explicitly given config, else the default.
fn resolve_admin_socket(args: &AdminSocketArgs, config_path: Option<&Path>) -> Result<PathBuf> {
    let socket = match (&args.socket, config_path) {
        (Some(socket), _) => socket.clone(),
        (None, Some(config_path)) => Config::load(config_path)?.server.admin_socket_path,
        (None, None) => PathBuf::from(DEFAULT_ADMIN_SOCKET_PATH),
    };
    let socket_metadata = fs::metadata(&socket)
        .with_context(|| format!("admin socket {} is not available", socket.display()))?;
    if !socket_metadata.file_type().is_socket() {
        bail!(
            "admin socket path {} is not a Unix socket",
            socket.display()
        );
    }
    Ok(socket)
}

fn admin_client(socket: &Path) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .unix_socket(socket)
        .timeout(Duration::from_secs(30))
        .build()
        .context("failed to create admin API client")
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

async fn unlock(args: UnlockArgs, config_path: Option<&Path>) -> Result<()> {
    if !valid_key_id(&args.key_id) {
        bail!("--key-id must match [A-Za-z0-9._-]{{1,128}}");
    }
    let socket = resolve_admin_socket(&args.admin, config_path)?;

    let prompt = format!("Passphrase for firmware signing key {}:", args.key_id);
    let passphrase = ask_password(&prompt)?;
    if passphrase.is_empty() {
        bail!("empty passphrase refused");
    }

    let url = format!("http://localhost/v1/unlock/{}", args.key_id);
    let response = admin_client(&socket)?
        .post(url)
        .json(&UnlockRequest {
            passphrase: passphrase.as_str(),
        })
        .send()
        .await
        .with_context(|| {
            format!(
                "failed to call admin API over Unix socket {}",
                socket.display()
            )
        })?;
    if !response.status().is_success() {
        return Err(response_error(response, "unlock").await);
    }

    println!("key {} is unlocked", args.key_id);
    Ok(())
}

async fn sign(args: SignArgs) -> Result<()> {
    if !valid_key_id(&args.key_id) {
        bail!("--key-id must match [A-Za-z0-9._-]{{1,128}}");
    }
    let decoded = BASE64
        .decode(args.digest.as_bytes())
        .context("--digest must be valid base64")?;
    if decoded.len() != 32 {
        bail!("--digest must decode to exactly 32 bytes");
    }

    let base_url = signer_base_url(&args.url)?;
    let endpoint = base_url
        .join(&format!("v1/sign/{}", args.key_id))
        .context("failed to construct signing API URL")?;
    let client = public_api_client()?;

    let token = if args.github_device {
        github_device_login(&client, &base_url).await?
    } else if let Some(token) = args.token {
        if token.is_empty() {
            bail!("--token must not be empty");
        }
        Zeroizing::new(token)
    } else {
        bail!(
            "no bearer credential was provided; set MICROTUN_SIGNER_TOKEN/--token, or pass --github-device for interactive GitHub authentication"
        );
    };

    let response = client
        .post(endpoint)
        .bearer_auth(token.as_str())
        .json(&SignRequest {
            digest: &args.digest,
        })
        .send()
        .await
        .context("failed to call signing API")?;
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
        .user_agent(concat!(
            "microtun-firmware-signer/",
            env!("CARGO_PKG_VERSION")
        ))
        .build()
        .context("failed to create signing API client")
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

    eprintln!(
        "GitHub authentication complete; signer session is valid for {} seconds.",
        session.expires_in
    );
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

fn ask_password(prompt: &str) -> Result<Zeroizing<String>> {
    let value = rpassword::prompt_password(format!("{prompt} "))
        .context("failed to read signing-key passphrase from the terminal")?;
    Ok(Zeroizing::new(value))
}

fn valid_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Look up a group ID by name with the reentrant getgrnam_r.
fn lookup_group_id(name: &str) -> Result<u32> {
    use std::ffi::{CStr, CString};

    let c_name = CString::new(name).context("group name contains a NUL byte")?;
    let mut buffer = vec![0 as libc::c_char; 16 * 1024];
    loop {
        // SAFETY: all pointers reference live, correctly sized buffers owned
        // by this frame; getgrnam_r writes only within them.
        let mut group: libc::group = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::group = std::ptr::null_mut();
        let rc = unsafe {
            libc::getgrnam_r(
                c_name.as_ptr(),
                &mut group,
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE && buffer.len() < 1024 * 1024 {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        if rc != 0 {
            bail!(
                "failed to look up group {name}: {}",
                std::io::Error::from_raw_os_error(rc)
            );
        }
        if result.is_null() {
            bail!("admin socket group {name} does not exist");
        }
        // SAFETY: getgrnam_r succeeded, so gr_name points into `buffer`.
        let found = unsafe { CStr::from_ptr(group.gr_name) };
        if found.to_bytes() != name.as_bytes() {
            bail!("group lookup for {name} returned a different group");
        }
        return Ok(group.gr_gid);
    }
}

fn bind_admin_socket(path: &Path, mode: u32, gid: Option<u32>) -> Result<tokio::net::UnixListener> {
    let parent = path.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "admin socket path {} has no parent directory",
            path.display()
        )
    })?;
    let parent_metadata = fs::metadata(parent).with_context(|| {
        format!(
            "failed to stat admin socket parent directory {}",
            parent.display()
        )
    })?;
    if !parent_metadata.is_dir() {
        bail!(
            "admin socket parent {} is not a directory",
            parent.display()
        );
    }
    let parent_mode = parent_metadata.permissions().mode() & 0o777;
    if parent_mode & 0o022 != 0 {
        bail!(
            "admin socket parent {} must not be writable by group/other users (mode {:03o})",
            parent.display(),
            parent_mode
        );
    }

    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.file_type().is_socket() {
            bail!(
                "refusing to replace non-socket admin path {}",
                path.display()
            );
        }
        fs::remove_file(path)
            .with_context(|| format!("failed to remove stale admin socket {}", path.display()))?;
    }

    let listener = tokio::net::UnixListener::bind(path)
        .with_context(|| format!("failed to bind admin socket {}", path.display()))?;
    // Change the group before widening the mode, so the socket is never
    // group-accessible to the wrong group. The unit's UMask=0077 keeps it
    // owner-only until then.
    if let Some(gid) = gid {
        std::os::unix::fs::chown(path, None, Some(gid)).with_context(|| {
            format!(
                "failed to set admin socket group on {} (is the service a member of the group?)",
                path.display()
            )
        })?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).with_context(|| {
        format!(
            "failed to set admin socket permissions on {}",
            path.display()
        )
    })?;
    Ok(listener)
}

struct AdminSocketGuard(PathBuf);

impl Drop for AdminSocketGuard {
    fn drop(&mut self) {
        let metadata = match fs::symlink_metadata(&self.0) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => {
                tracing::warn!(
                    socket = %self.0.display(),
                    error = %error,
                    "failed to stat admin socket during shutdown"
                );
                return;
            }
        };
        if !metadata.file_type().is_socket() {
            tracing::warn!(
                socket = %self.0.display(),
                "refusing to remove admin path because it is no longer a Unix socket"
            );
            return;
        }
        if let Err(error) = fs::remove_file(&self.0) {
            tracing::warn!(
                socket = %self.0.display(),
                error = %error,
                "failed to remove admin socket during shutdown"
            );
        }
    }
}

async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    while shutdown.changed().await.is_ok() {
        if *shutdown.borrow() {
            return;
        }
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("microtun_firmware_signer=info,tower_http=info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .with_target(false)
        .init();
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }

    tracing::info!("shutdown signal received");
}

#[cfg(test)]
mod cli_tests {
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
        let mut response = axum::http::Response::builder()
            .status(reqwest::StatusCode::OK)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(br#"{"error":"authorization_pending"}"#.to_vec())
            .unwrap();

        normalize_github_oauth_error_response(&mut response);

        assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn github_oauth_200_success_is_not_normalized() {
        let mut response = axum::http::Response::builder()
            .status(reqwest::StatusCode::OK)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(br#"{"access_token":"token","token_type":"bearer"}"#.to_vec())
            .unwrap();

        normalize_github_oauth_error_response(&mut response);

        assert_eq!(response.status(), reqwest::StatusCode::OK);
    }
}
