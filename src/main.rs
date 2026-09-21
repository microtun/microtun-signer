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
        AppState, UnlockState, create_signature, get_public_key, github_oauth_callback,
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
        short = 'c',
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
    #[arg(short = 'k', long)]
    key: String,

    /// Unix-domain socket exposed by the signer's local admin API.
    #[arg(short = 's', long, env = "MICROTUN_SIGNER_ADMIN_SOCKET")]
    socket: Option<PathBuf>,
}

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
        .route("/v1/auth/github", get(github_oauth_login))
        .route("/v1/auth/github/callback", get(github_oauth_callback))
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
        .with_state(UnlockState { keys });

    let listener = tokio::net::TcpListener::bind(config.server.listen)
        .await
        .with_context(|| format!("failed to bind {}", config.server.listen))?;
    let admin_listener = bind_admin_socket(
        &config.server.admin_socket_path,
        config.server.admin_socket_mode,
    )?;
    let _admin_socket_guard = AdminSocketGuard(config.server.admin_socket_path.clone());

    tracing::info!(
        listen = %config.server.listen,
        "firmware signing service started"
    );
    tracing::info!(
        socket = %config.server.admin_socket_path.display(),
        mode = %format_args!("{:03o}", config.server.admin_socket_mode),
        "local admin API started"
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    });

    let public_server =
        axum::serve(listener, app).with_graceful_shutdown(wait_for_shutdown(shutdown_rx.clone()));
    let admin_server = axum::serve(admin_listener, admin_app)
        .with_graceful_shutdown(wait_for_shutdown(shutdown_rx));

    tokio::try_join!(public_server, admin_server).context("HTTP server failed")?;
    Ok(())
}

async fn unlock(args: UnlockArgs, config_path: &Path) -> Result<()> {
    if !valid_key_id(&args.key) {
        bail!("--key must match [A-Za-z0-9._-]{{1,128}}");
    }

    let socket = match args.socket {
        Some(socket) => socket,
        None => Config::load(config_path)?.server.admin_socket_path,
    };

    let socket_metadata = fs::metadata(&socket)
        .with_context(|| format!("admin socket {} is not available", socket.display()))?;
    if !socket_metadata.file_type().is_socket() {
        bail!(
            "admin socket path {} is not a Unix socket",
            socket.display()
        );
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
        .context("failed to create admin API client")?;
    let url = format!("http://localhost/v1/unlock/{}", args.key);
    let response = client
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

    let status = response.status();
    if !status.is_success() {
        let body = response
            .bytes()
            .await
            .context("failed to read admin API response")?;
        if let Ok(problem) = serde_json::from_slice::<ErrorBody>(&body) {
            bail!(
                "unlock failed: {} (request {})",
                problem.error,
                problem.request_id
            );
        }
        bail!("unlock failed with HTTP status {status}");
    }

    println!("key {} is unlocked", args.key);
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

fn bind_admin_socket(path: &Path, mode: u32) -> Result<tokio::net::UnixListener> {
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
    use super::*;

    #[test]
    fn short_options_parse_like_long_options() {
        let cli = Cli::try_parse_from([
            "microtun-firmware-signer",
            "-c",
            "/tmp/config.toml",
            "unlock",
            "-k",
            "test-key",
            "-s",
            "/tmp/unlock.sock",
        ])
        .expect("short CLI options should parse");

        assert_eq!(cli.config, PathBuf::from("/tmp/config.toml"));
        match cli.command {
            Some(Commands::Unlock(args)) => {
                assert_eq!(args.key, "test-key");
                assert_eq!(args.socket, Some(PathBuf::from("/tmp/unlock.sock")));
            }
            None => panic!("expected unlock subcommand"),
        }
    }
}
