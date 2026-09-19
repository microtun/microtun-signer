mod api;
mod auth;
mod authorization;
mod config;
mod key;

use std::{path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post},
};
use clap::Parser;
use tower_http::{catch_panic::CatchPanicLayer, trace::TraceLayer};
use tracing_subscriber::EnvFilter;

use crate::{
    api::{AppState, create_signature, get_key, github_oauth_callback, github_oauth_login, health},
    auth::Authenticator,
    authorization::Authorizer,
    config::Config,
    key::KeyRing,
};

#[derive(Debug, Parser)]
#[command(name = "microtun-firmware-signer", version)]
struct Args {
    /// Path to the service TOML configuration.
    #[arg(long, env = "MICROTUN_SIGNER_CONFIG", default_value = "config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let args = Args::parse();
    let config = Config::load(&args.config)?;

    let keys = Arc::new(KeyRing::load(&config.keys)?);
    for key in keys.iter() {
        tracing::info!(
            key_id = key.id(),
            key_fingerprint = key.fingerprint(),
            key_state = key.state().as_str(),
            "loaded encrypted firmware signing key into memory"
        );
    }
    tracing::info!(key_count = keys.len(), "firmware signing keyring loaded");

    let authenticator = Authenticator::new(
        config.github.clone(),
        config.github_actions.clone(),
        config.identities.clone(),
    )
    .context("failed to initialize GitHub identity authentication client")?;
    let authorizer = Authorizer::new(config.policies.clone());

    let state = AppState {
        keys,
        auth: authenticator,
        authz: authorizer,
    };

    let api = Router::new()
        .route("/healthz", get(health))
        .route("/v1/auth/github/login", get(github_oauth_login))
        .route("/v1/auth/github/callback", get(github_oauth_callback))
        .route("/v1/keys/{key_id}", get(get_key))
        .route("/v1/signatures", post(create_signature))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(CatchPanicLayer::new())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let app = if config.server.base_path.is_empty() {
        api
    } else {
        Router::new().nest(&config.server.base_path, api)
    };

    let listener = tokio::net::TcpListener::bind(config.server.listen)
        .await
        .with_context(|| format!("failed to bind {}", config.server.listen))?;
    tracing::info!(
        listen = %config.server.listen,
        base_path = %config.server.base_path,
        "firmware signing service started"
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("HTTP server failed")?;
    Ok(())
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
