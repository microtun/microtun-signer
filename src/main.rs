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
use clap::{Parser, Subcommand};
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
#[command(name = "microtun-signer", version)]
struct Cli {
    /// Path to the service TOML configuration
    /// [default: /etc/microtun-signer/config.toml].
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

const DEFAULT_CONFIG_PATH: &str = "/etc/microtun-signer/config.toml";

#[derive(Serialize)]
struct UnlockRequest<'a> {
    passphrase: &'a str,
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
        "microtun signer service started"
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
        .unwrap_or_else(|_| EnvFilter::new("microtun_signer=info,tower_http=info"));
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
