mod api;
mod auth;
mod authorization;
mod config;
mod key;

use std::{
    fs,
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
        AppState, UnlockState, create_signature, get_key, github_oauth_callback,
        github_oauth_login, health, unlock_key,
    },
    auth::Authenticator,
    authorization::Authorizer,
    config::Config,
    key::KeyRing,
};

#[derive(Debug, Parser)]
#[command(name = "microtun-firmware-signer", version)]
struct Cli {
    /// Path to the service TOML configuration.
    #[arg(
        long,
        env = "MICROTUN_SIGNER_CONFIG",
        global = true,
        default_value = "/etc/microtun-firmware-signer/config.toml"
    )]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Interactively unlock an active signing key through the local management socket.
    Unlock(UnlockArgs),
}

#[derive(Debug, clap::Args)]
struct UnlockArgs {
    /// Immutable signing key ID to unlock.
    #[arg(long)]
    key: String,

    /// Unix-domain socket exposed by the signer's local unlock API.
    #[arg(long, env = "MICROTUN_SIGNER_UNLOCK_SOCKET")]
    socket: Option<PathBuf>,
}

#[derive(Serialize)]
struct UnlockRequest<'a> {
    passphrase: &'a str,
}

#[derive(Deserialize)]
struct UnlockResponse {
    request_id: String,
    already_unlocked: bool,
    key: UnlockKey,
}

#[derive(Deserialize)]
struct UnlockKey {
    id: String,
    lock_state: String,
}

#[derive(Deserialize)]
struct ProblemBody {
    title: String,
    detail: String,
    request_id: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let Cli { config, command } = Cli::parse();
    match command {
        Some(Commands::Unlock(args)) => unlock(args, &config).await,
        None => run_server(config).await,
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

    let state = AppState {
        keys: keys.clone(),
        auth: authenticator,
        authz: authorizer,
    };

    let app = Router::new()
        .route("/healthz", get(health))
        .route("/v1/auth/github/login", get(github_oauth_login))
        .route("/v1/auth/github/callback", get(github_oauth_callback))
        .route("/v1/keys/{key_id}", get(get_key))
        .route("/v1/keys/{key_id}/signatures", post(create_signature))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(CatchPanicLayer::new())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // The unlock API deliberately lives on a separate Unix-domain socket. It
    // must never be added to the public TCP router or reverse-proxied.
    let unlock_app = Router::new()
        .route("/v1/keys/{key_id}/unlock", post(unlock_key))
        .layer(DefaultBodyLimit::max(8 * 1024))
        .layer(CatchPanicLayer::new())
        .layer(TraceLayer::new_for_http())
        .with_state(UnlockState { keys });

    let listener = tokio::net::TcpListener::bind(config.server.listen)
        .await
        .with_context(|| format!("failed to bind {}", config.server.listen))?;
    let unlock_listener =
        bind_unlock_socket(&config.unlock.socket_path, config.unlock.socket_mode)?;
    let _unlock_socket_guard = UnlockSocketGuard(config.unlock.socket_path.clone());

    tracing::info!(
        listen = %config.server.listen,
        "firmware signing service started"
    );
    tracing::info!(
        socket = %config.unlock.socket_path.display(),
        mode = %format_args!("{:03o}", config.unlock.socket_mode),
        "local key unlock API started"
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    });

    let public_server =
        axum::serve(listener, app).with_graceful_shutdown(wait_for_shutdown(shutdown_rx.clone()));
    let unlock_server = axum::serve(unlock_listener, unlock_app)
        .with_graceful_shutdown(wait_for_shutdown(shutdown_rx));

    tokio::try_join!(public_server, unlock_server).context("HTTP server failed")?;
    Ok(())
}

async fn unlock(args: UnlockArgs, config_path: &Path) -> Result<()> {
    if !valid_key_id(&args.key) {
        bail!("--key must match [A-Za-z0-9._-]{{1,128}}");
    }

    let socket = match args.socket {
        Some(socket) => socket,
        None => Config::load(config_path)?.unlock.socket_path,
    };

    let socket_metadata = fs::metadata(&socket)
        .with_context(|| format!("unlock socket {} is not available", socket.display()))?;
    if !socket_metadata.file_type().is_socket() {
        bail!("unlock path {} is not a Unix socket", socket.display());
    }

    let prompt = format!("Passphrase for firmware signing key {}:", args.key);
    let passphrase = ask_password(&prompt)?;
    if passphrase.is_empty() {
        bail!("empty passphrase refused");
    }

    let client = reqwest::Client::builder()
        .unix_socket(socket.as_path())
        .timeout(Duration::from_secs(30))
        .build()
        .context("failed to create unlock API client")?;
    let url = format!("http://localhost/v1/keys/{}/unlock", args.key);
    let response = client
        .post(url)
        .json(&UnlockRequest {
            passphrase: passphrase.as_str(),
        })
        .send()
        .await
        .with_context(|| {
            format!(
                "failed to call unlock API over Unix socket {}",
                socket.display()
            )
        })?;

    let status = response.status();
    let body = response
        .bytes()
        .await
        .context("failed to read unlock API response")?;
    if !status.is_success() {
        if let Ok(problem) = serde_json::from_slice::<ProblemBody>(&body) {
            bail!(
                "unlock failed: {}: {} (request {})",
                problem.title,
                problem.detail,
                problem.request_id
            );
        }
        bail!("unlock failed with HTTP status {status}");
    }

    let unlocked: UnlockResponse =
        serde_json::from_slice(&body).context("unlock API returned an invalid success response")?;
    if unlocked.key.lock_state != "unlocked" {
        bail!("unlock API returned success but key is not unlocked");
    }
    if unlocked.already_unlocked {
        println!(
            "key {} was already unlocked; request {}",
            unlocked.key.id, unlocked.request_id
        );
    } else {
        println!(
            "unlocked key {}; request {}",
            unlocked.key.id, unlocked.request_id
        );
    }
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

fn bind_unlock_socket(path: &Path, mode: u32) -> Result<tokio::net::UnixListener> {
    let parent = path.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "unlock socket path {} has no parent directory",
            path.display()
        )
    })?;
    let parent_metadata = fs::metadata(parent).with_context(|| {
        format!(
            "failed to stat unlock socket parent directory {}",
            parent.display()
        )
    })?;
    if !parent_metadata.is_dir() {
        bail!(
            "unlock socket parent {} is not a directory",
            parent.display()
        );
    }
    let parent_mode = parent_metadata.permissions().mode() & 0o777;
    if parent_mode & 0o022 != 0 {
        bail!(
            "unlock socket parent {} must not be writable by group/other users (mode {:03o})",
            parent.display(),
            parent_mode
        );
    }

    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.file_type().is_socket() {
            bail!(
                "refusing to replace non-socket unlock path {}",
                path.display()
            );
        }
        fs::remove_file(path)
            .with_context(|| format!("failed to remove stale unlock socket {}", path.display()))?;
    }

    let listener = tokio::net::UnixListener::bind(path)
        .with_context(|| format!("failed to bind unlock socket {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).with_context(|| {
        format!(
            "failed to set unlock socket permissions on {}",
            path.display()
        )
    })?;
    Ok(listener)
}

struct UnlockSocketGuard(PathBuf);

impl Drop for UnlockSocketGuard {
    fn drop(&mut self) {
        let metadata = match fs::symlink_metadata(&self.0) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => {
                tracing::warn!(
                    socket = %self.0.display(),
                    error = %error,
                    "failed to stat unlock socket during shutdown"
                );
                return;
            }
        };
        if !metadata.file_type().is_socket() {
            tracing::warn!(
                socket = %self.0.display(),
                "refusing to remove unlock path because it is no longer a Unix socket"
            );
            return;
        }
        if let Err(error) = fs::remove_file(&self.0) {
            tracing::warn!(
                socket = %self.0.display(),
                error = %error,
                "failed to remove unlock socket during shutdown"
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
