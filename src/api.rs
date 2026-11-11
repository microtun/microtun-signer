use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, LazyLock},
    time::Duration,
};

use axum::{
    Form, Json, Router,
    body::{Body, Bytes},
    extract::{ConnectInfo, Path, Query, State, rejection::FormRejection},
    http::{
        HeaderMap, HeaderName, HeaderValue, Request, StatusCode,
        header::{
            CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, COOKIE, LOCATION, ORIGIN, PRAGMA,
            REFERRER_POLICY, RETRY_AFTER, SET_COOKIE, WWW_AUTHENTICATE, X_CONTENT_TYPE_OPTIONS,
            X_FRAME_OPTIONS,
        },
    },
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::sync::Semaphore;
use tower_governor::{
    GovernorError, GovernorLayer, governor::GovernorConfigBuilder, key_extractor::KeyExtractor,
};
use ulid::Ulid;

use crate::{
    auth::{AuthError, AuthPrincipal, AuthSource, Authenticator, OAuthFlowError},
    authorization::Authorizer,
    config::{KeyState, PolicyAction, valid_key_id, valid_keyring_name},
    key::{
        KeyStore, KeyringMemberOutcome, KeyringUnlockError, SignError, UnlockError, UnlockOutcome,
    },
    oauth::{
        Account, AuthorizationRequest, CLI_CLIENT_ID, GrantError, new_browser_token, same_token,
        valid_browser_token, verification_code,
    },
};
use zeroize::Zeroizing;

/// Rate limit on the browser-facing login endpoints, per client address: a
/// burst of this many requests, replenished one at a time. A login passes
/// through three of them (the confirmation page, its form, then the GitHub
/// callback).
const LOGIN_BURST: u32 = 30;
const LOGIN_REPLENISH_INTERVAL: Duration = Duration::from_secs(2);
/// GitHub callbacks handled at once; each one makes the signer call GitHub.
const LOGIN_MAX_CONCURRENT: usize = 8;

#[derive(Clone)]
pub struct AppState {
    pub keys: Arc<KeyStore>,
    pub auth: Authenticator,
    pub authz: Authorizer,
    login_permits: Arc<Semaphore>,
}

impl AppState {
    pub fn new(keys: Arc<KeyStore>, auth: Authenticator, authz: Authorizer) -> Self {
        Self {
            keys,
            auth,
            authz,
            login_permits: Arc::new(Semaphore::new(LOGIN_MAX_CONCURRENT)),
        }
    }
}

/// Rate-limiting key: the address of the client as far as it can be trusted.
///
/// Without `Server.ClientIPHeader` that is the TCP peer, which behind a
/// reverse proxy is the proxy for everyone. With it, it is the last address
/// in that header, i.e. the one the directly connected proxy wrote. Earlier
/// entries are whatever the client chose to send and are ignored.
#[derive(Clone)]
struct ClientIpKeyExtractor {
    header: Option<HeaderName>,
}

impl KeyExtractor for ClientIpKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, request: &Request<T>) -> Result<IpAddr, GovernorError> {
        let peer = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(peer)| peer.ip());
        client_ip(self.header.as_ref(), request.headers(), peer)
            .ok_or(GovernorError::UnableToExtractKey)
    }
}

fn client_ip(
    header: Option<&HeaderName>,
    headers: &HeaderMap,
    peer: Option<IpAddr>,
) -> Option<IpAddr> {
    header
        .and_then(|name| headers.get_all(name).iter().next_back())
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.rsplit(',').next())
        .and_then(|address| address.trim().parse().ok())
        .or(peer)
}

/// Put the login rate limit in front of the browser-facing login routes.
/// Must be called from within the Tokio runtime.
pub fn rate_limit_logins(
    routes: Router<AppState>,
    client_ip_header: Option<HeaderName>,
) -> Router<AppState> {
    let config = Arc::new(
        GovernorConfigBuilder::default()
            .period(LOGIN_REPLENISH_INTERVAL)
            .burst_size(LOGIN_BURST)
            .key_extractor(ClientIpKeyExtractor {
                header: client_ip_header,
            })
            .finish()
            .expect("login rate limit is non-zero"),
    );

    // The limiter remembers every address it has seen; forget idle ones.
    let limiter = Arc::downgrade(config.limiter());
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            match limiter.upgrade() {
                Some(limiter) => limiter.retain_recent(),
                None => break,
            }
        }
    });

    routes.layer(GovernorLayer::new(config).error_handler(login_rate_limit_response))
}

fn login_rate_limit_response(error: GovernorError) -> axum::http::Response<Body> {
    let request_id = Ulid::new().to_string();
    match error {
        GovernorError::TooManyRequests { wait_time, .. } => {
            let mut response = ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "oauth-login-rate-limited",
                "Too many sign-in attempts",
                "Wait before attempting another GitHub sign-in from this source.",
                &request_id,
            )
            .into_response();
            response
                .headers_mut()
                .insert(RETRY_AFTER, HeaderValue::from(wait_time.max(1)));
            response
        }
        GovernorError::UnableToExtractKey | GovernorError::Other { .. } => ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal-error",
            "Internal error",
            "The client address could not be determined.",
            &request_id,
        )
        .into_response(),
    }
}

/// State for the local-only admin API served on the Unix-domain socket.
#[derive(Clone)]
pub struct AdminState {
    pub keys: Arc<KeyStore>,
    /// Allows one key decryption at a time. Each attempt runs a deliberately
    /// expensive KDF (scrypt may use up to 1 GiB), so concurrent attempts are
    /// queued rather than multiplied.
    pub unlock_permits: Arc<Semaphore>,
}

impl AdminState {
    pub fn new(keys: Arc<KeyStore>) -> Self {
        Self {
            keys,
            unlock_permits: Arc::new(Semaphore::new(1)),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct AuditRecord {
    request_id: String,
    operation: String,
    success: bool,
    reason: String,
    key_id: Option<String>,
    firmware_digest: Option<String>,
    identity_id: Option<String>,
    principal: Option<String>,
    auth_method: Option<String>,
    issuer: Option<String>,
    audience: Option<String>,
    subject: Option<String>,
    github_login: Option<String>,
    github_user_id: Option<String>,
    actor: Option<String>,
    actor_id: Option<String>,
    repository: Option<String>,
    repository_id: Option<String>,
    git_ref: Option<String>,
    ref_protected: Option<bool>,
    environment: Option<String>,
    commit_sha: Option<String>,
    event_name: Option<String>,
    workflow_ref: Option<String>,
    run_id: Option<String>,
    run_attempt: Option<String>,
    jti: Option<String>,
}

pub async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}

#[derive(Serialize)]
pub struct VersionResponse {
    version: &'static str,
}

pub async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION"),
    })
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeParams {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
}

/// The cookie that identifies one browser for the length of a sign-in. It
/// does two jobs: its value is repeated in the confirmation form, so a form
/// that was not served to this browser is refused (CSRF), and its digest is
/// stored with the pending login, so GitHub's redirect is only honoured in
/// the browser that confirmed (a GitHub link prepared elsewhere is useless).
///
/// The `__Host-` prefix makes browsers refuse the cookie unless it is Secure,
/// host-only and has `Path=/`, so no sibling subdomain can plant one. It is
/// not available on the plain-HTTP loopback URL used for local development.
const LOGIN_COOKIE_SECURE: &str = "__Host-mts-login";
const LOGIN_COOKIE_INSECURE: &str = "mts-login";
/// Matches how long the signer remembers an unfinished sign-in.
const LOGIN_COOKIE_MAX_AGE_SECONDS: u64 = 10 * 60;

fn login_cookie_name(auth: &Authenticator) -> &'static str {
    if auth.public_url_is_https() {
        LOGIN_COOKIE_SECURE
    } else {
        LOGIN_COOKIE_INSECURE
    }
}

/// The well-formed login cookie this browser sent, if any.
fn login_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(cookie, _)| *cookie == name)
        .map(|(_, value)| value.to_owned())
        .filter(|value| valid_browser_token(value))
}

/// `SameSite=Lax` and not `Strict`: the cookie has to come back on the
/// top-level navigation from github.com to the callback.
fn set_login_cookie(auth: &Authenticator, value: &str) -> Option<HeaderValue> {
    let secure = if auth.public_url_is_https() {
        "; Secure"
    } else {
        ""
    };
    HeaderValue::from_str(&format!(
        "{}={value}; Path=/; Max-Age={LOGIN_COOKIE_MAX_AGE_SECONDS}; HttpOnly; SameSite=Lax{secure}",
        login_cookie_name(auth)
    ))
    .ok()
}

const CONFIRMATION_PAGE_STYLE: &str = "\
:root{color-scheme:light dark}\
body{margin:0;font:16px/1.5 system-ui,sans-serif}\
main{max-width:34rem;margin:0 auto;padding:3rem 1.25rem}\
h1{font-size:1.4rem;margin:0 0 1rem}\
.code{font:600 2rem/1.2 ui-monospace,monospace;letter-spacing:.12em;\
padding:1rem;margin:1.5rem 0;text-align:center;border:2px solid;border-radius:.5rem}\
.warn{font-weight:600}\
button{font:inherit;font-weight:600;padding:.7rem 1.4rem;margin-top:1rem;cursor:pointer}\
small{display:block;margin-top:2rem;opacity:.75}";

/// The confirmation page may load nothing and run nothing: only its own
/// style block, identified by hash. `frame-ancestors 'none'` keeps the button
/// from being clicked through an invisible frame on another site.
///
/// There is deliberately no `form-action` directive. Browsers also apply it
/// to the redirect that answers the form, which would block the hop to GitHub.
static CONFIRMATION_PAGE_CSP: LazyLock<String> = LazyLock::new(|| {
    format!(
        "default-src 'none'; style-src 'sha256-{}'; frame-ancestors 'none'; base-uri 'none'",
        BASE64.encode(Sha256::digest(CONFIRMATION_PAGE_STYLE.as_bytes()))
    )
});

fn html_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// The page a browser gets at the authorization endpoint. Everything taken
/// from the request is HTML-escaped; nothing else from the query is shown.
fn confirmation_page(auth: &Authenticator, request: &AuthorizationRequest, csrf: &str) -> String {
    // Validation guarantees a loopback literal with an explicit port.
    let listener = reqwest::Url::parse(&request.redirect_uri)
        .ok()
        .and_then(|url| Some(format!("{}:{}", url.host_str()?, url.port()?)))
        .unwrap_or_default();
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Sign in to microtun-signer</title>
<style>{style}</style>
</head>
<body>
<main>
<h1>Sign in to microtun-signer</h1>
<p>A <code>microtun-signer</code> command is asking to sign in with your GitHub account. Its terminal shows a verification code. Check that it is this one:</p>
<p class="code">{code}</p>
<p class="warn">Continue only if you started that command yourself and the codes match.</p>
<p>If you got here from a link someone sent you, or no terminal of yours shows this code, close this page. Continuing would let whoever sent the link sign firmware as you.</p>
<form method="post" action="{action}">
<input type="hidden" name="redirect_uri" value="{redirect_uri}">
<input type="hidden" name="state" value="{state}">
<input type="hidden" name="code_challenge" value="{code_challenge}">
<input type="hidden" name="csrf" value="{csrf}">
<button type="submit">The codes match &ndash; continue to GitHub</button>
</form>
<small>After GitHub, the result is delivered to the command listening on {listener} on this computer.</small>
</main>
</body>
</html>
"#,
        style = CONFIRMATION_PAGE_STYLE,
        code = html_escape(&verification_code(&request.code_challenge)),
        action = html_escape(auth.authorize_endpoint()),
        redirect_uri = html_escape(&request.redirect_uri),
        state = html_escape(&request.state),
        code_challenge = html_escape(&request.code_challenge),
        csrf = html_escape(csrf),
        listener = html_escape(&listener),
    )
}

/// A plain-text answer for a person looking at a browser tab.
fn login_refused(status: StatusCode, message: &'static str) -> Response {
    let mut response = no_store((status, message));
    response
        .headers_mut()
        .insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    response
}

/// OAuth 2.0 authorization endpoint for the signer CLI (authorization code
/// flow with PKCE, loopback redirect).
///
/// A request here proves nothing about who built it: the CLI is a public
/// client, and anyone can put their own PKCE challenge and loopback port into
/// such a URL and send it to a maintainer. GitHub does not ask again once the
/// OAuth App is authorized, so the signer must not pass the browser straight
/// on. It shows a confirmation page instead, and nothing is remembered and
/// GitHub is not involved until the person presses the button on it.
pub async fn oauth_authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<AuthorizeParams>,
) -> Result<Response, ApiError> {
    let request_id = Ulid::new().to_string();

    // Nothing is redirected to the client on a malformed request: only the
    // CLI builds these URLs, and an unvalidated redirect_uri must not be used.
    let invalid = || {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid-authorization-request",
            "Invalid authorization request",
            "Expected response_type=code, the signer CLI client_id, a loopback redirect_uri, state, and an S256 code_challenge.",
            &request_id,
        )
    };
    if params.response_type.as_deref() != Some("code")
        || params.client_id.as_deref() != Some(CLI_CLIENT_ID)
        || params.code_challenge_method.as_deref() != Some("S256")
    {
        return Err(invalid());
    }
    let request = AuthorizationRequest::new(
        params.redirect_uri.as_deref().unwrap_or_default(),
        params.state.as_deref().unwrap_or_default(),
        params.code_challenge.as_deref().unwrap_or_default(),
    )
    .map_err(|_| invalid())?;

    // Keep the cookie a browser already has, so that a second sign-in tab
    // does not invalidate the form in the first one.
    let browser_token =
        login_cookie(&headers, login_cookie_name(&state.auth)).unwrap_or_else(new_browser_token);
    let cookie = set_login_cookie(&state.auth, &browser_token).ok_or_else(|| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal-error",
            "Internal error",
            "The sign-in cookie could not be created.",
            &request_id,
        )
    })?;

    let page = confirmation_page(&state.auth, &request, &browser_token);
    let mut response = no_store(([(CONTENT_TYPE, "text/html; charset=utf-8")], page));
    let response_headers = response.headers_mut();
    response_headers.insert(SET_COOKIE, cookie);
    if let Ok(policy) = HeaderValue::from_str(&CONFIRMATION_PAGE_CSP) {
        response_headers.insert(CONTENT_SECURITY_POLICY, policy);
    }
    response_headers.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    response_headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    // Not `no-referrer`: under that policy browsers submit the form with
    // `Origin: null`, and the form handler below could not tell where it came
    // from. `same-origin` still keeps this URL away from GitHub.
    response_headers.insert(REFERRER_POLICY, HeaderValue::from_static("same-origin"));
    Ok(response)
}

#[derive(Deserialize)]
pub struct AuthorizeConfirmation {
    redirect_uri: String,
    state: String,
    code_challenge: String,
    csrf: String,
}

/// The confirmation page's form: the person pressed the button. Only now is
/// the sign-in remembered and the browser sent on to GitHub.
///
/// The request must demonstrably come from the page this signer served to
/// this browser: the `Origin` header has to be the signer's own, and the
/// form has to repeat the value of the login cookie, which no other site can
/// read or set.
pub async fn oauth_authorize_confirm(
    State(state): State<AppState>,
    headers: HeaderMap,
    form: Result<Form<AuthorizeConfirmation>, FormRejection>,
) -> Response {
    let request_id = Ulid::new().to_string();
    let Ok(Form(form)) = form else {
        return login_refused(
            StatusCode::BAD_REQUEST,
            "This sign-in form is incomplete. Run the microtun-signer command again.\n",
        );
    };

    let same_origin = headers
        .get(ORIGIN)
        .and_then(|origin| origin.to_str().ok())
        .is_some_and(|origin| origin == state.auth.public_origin());
    let confirmed_here = login_cookie(&headers, login_cookie_name(&state.auth))
        .filter(|cookie| same_token(cookie, &form.csrf));
    let (true, Some(browser_token)) = (same_origin, confirmed_here) else {
        audit_login(
            &request_id,
            "oauth-login-confirm",
            false,
            "confirmation did not come from the signer's own page in this browser",
            None,
        );
        return login_refused(
            StatusCode::FORBIDDEN,
            "This sign-in could not be confirmed: the request did not come from the signer's own page in this browser. Run the microtun-signer command again and open the link it prints. Cookies must be enabled for this site.\n",
        );
    };

    let Ok(request) =
        AuthorizationRequest::new(&form.redirect_uri, &form.state, &form.code_challenge)
    else {
        return login_refused(
            StatusCode::BAD_REQUEST,
            "This sign-in form is invalid. Run the microtun-signer command again.\n",
        );
    };

    match state.auth.begin_github_login(request, &browser_token) {
        // 303 turns the browser's POST into a GET of the GitHub URL.
        Ok(github_url) => browser_redirect(StatusCode::SEE_OTHER, &github_url),
        Err(_) => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "oauth-capacity-exhausted",
            "GitHub sign-in is temporarily unavailable",
            "The signer is tracking too many unfinished sign-ins.",
            &request_id,
        )
        .into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct GithubCallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// Where GitHub sends the browser back to. If this is the browser that
/// confirmed the sign-in, the signer exchanges GitHub's code itself, checks
/// the account, and then redirects the browser to the CLI's loopback listener
/// with a signer authorization code (or an OAuth error).
pub async fn github_oauth_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<GithubCallbackParams>,
) -> Response {
    let request_id = Ulid::new().to_string();
    let Ok(_permit) = state.login_permits.clone().try_acquire_owned() else {
        return ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "oauth-login-busy",
            "GitHub sign-in is busy",
            "The signer is already processing the maximum number of GitHub sign-ins.",
            &request_id,
        )
        .into_response();
    };

    // An unknown state cannot be tied to any CLI, so there is nowhere safe to
    // redirect to and nothing is asked of GitHub.
    let Some(pending) = params
        .state
        .as_deref()
        .and_then(|github_state| state.auth.take_pending_login(github_state))
    else {
        return no_store((
            StatusCode::BAD_REQUEST,
            "This sign-in link has expired or was already used. Run the microtun-signer command again.\n",
        ));
    };

    // The sign-in is finished only in the browser that confirmed it. Someone
    // who confirmed in their own browser and passed the resulting GitHub link
    // on gets nothing: the code is not exchanged and nothing is sent to the
    // loopback port they chose. The pending login is already consumed.
    let same_browser = login_cookie(&headers, login_cookie_name(&state.auth))
        .is_some_and(|cookie| pending.confirmed_by(&cookie));
    if !same_browser {
        audit_login(
            &request_id,
            "oauth-login",
            false,
            "GitHub redirect arrived in a browser that did not confirm the sign-in",
            None,
        );
        return login_refused(
            StatusCode::FORBIDDEN,
            "This sign-in was not started in this browser, so it was cancelled. If you followed a link someone sent you, do not retry it. Otherwise run the microtun-signer command again and finish in the browser that opened its link.
",
        );
    }

    let outcome = match params.code.as_deref() {
        Some(code) if params.error.is_none() => {
            state.auth.finish_github_login(&pending, code).await
        }
        _ => Err(OAuthFlowError::AuthorizationDenied),
    };
    let Ok(mut redirect) = reqwest::Url::parse(&pending.request.redirect_uri) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    match outcome {
        Ok((code, account)) => {
            audit_login(&request_id, "oauth-login", true, "ok", Some(&account));
            redirect.query_pairs_mut().append_pair("code", &code);
        }
        Err(error) => {
            audit_login(&request_id, "oauth-login", false, &error.to_string(), None);
            redirect
                .query_pairs_mut()
                .append_pair("error", oauth_redirect_error_code(&error))
                .append_pair("error_description", &error.to_string());
        }
    }
    redirect
        .query_pairs_mut()
        .append_pair("state", &pending.request.state);
    browser_redirect(StatusCode::FOUND, &redirect)
}

#[derive(Deserialize)]
pub struct TokenRequest {
    grant_type: Option<String>,
    client_id: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
}

/// RFC 6749 section 5.2 error body, which is what OAuth client libraries
/// expect from a token endpoint instead of the signer's usual error shape.
#[derive(Serialize)]
struct TokenErrorResponse {
    error: &'static str,
    error_description: &'static str,
}

fn token_error(status: StatusCode, error: &'static str, description: &'static str) -> Response {
    no_store((
        status,
        Json(TokenErrorResponse {
            error,
            error_description: description,
        }),
    ))
}

/// OAuth 2.0 token endpoint: `authorization_code` (with PKCE) and
/// `refresh_token` grants for the signer CLI. Neither grant contacts GitHub.
pub async fn oauth_token(
    State(state): State<AppState>,
    form: Result<Form<TokenRequest>, FormRejection>,
) -> Response {
    let request_id = Ulid::new().to_string();
    let Ok(Form(request)) = form else {
        return token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "The token request must be application/x-www-form-urlencoded.",
        );
    };
    let code = request.code.map(Zeroizing::new);
    let refresh_token = request.refresh_token.map(Zeroizing::new);
    if request.client_id.as_deref() != Some(CLI_CLIENT_ID) {
        return token_error(
            StatusCode::BAD_REQUEST,
            "invalid_client",
            "Unknown client_id.",
        );
    }

    let (operation, outcome) = match request.grant_type.as_deref() {
        Some("authorization_code") => {
            let (Some(code), Some(redirect_uri), Some(code_verifier)) =
                (code, request.redirect_uri, request.code_verifier)
            else {
                return token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "code, redirect_uri, and code_verifier are required.",
                );
            };
            (
                "oauth-token",
                state
                    .auth
                    .redeem_authorization_code(&code, &redirect_uri, &code_verifier),
            )
        }
        Some("refresh_token") => {
            let Some(refresh_token) = refresh_token else {
                return token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "refresh_token is required.",
                );
            };
            ("oauth-refresh", state.auth.refresh_session(&refresh_token))
        }
        _ => {
            return token_error(
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                "Supported grant types are authorization_code and refresh_token.",
            );
        }
    };

    match outcome {
        Ok((tokens, account)) => {
            audit_login(&request_id, operation, true, "ok", Some(&account));
            no_store(Json(TokenResponse {
                access_token: tokens.access_token,
                token_type: "Bearer",
                expires_in: tokens.expires_in,
                refresh_token: tokens.refresh_token,
            }))
        }
        Err(GrantError::RefreshTokenReused(account)) => {
            audit_login(
                &request_id,
                operation,
                false,
                "refresh token reuse detected; login revoked",
                Some(&account),
            );
            token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "The refresh token was already used; sign in again.",
            )
        }
        Err(GrantError::Invalid) => {
            audit_login(&request_id, operation, false, "invalid grant", None);
            token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "The authorization code or refresh token is invalid or expired.",
            )
        }
        Err(GrantError::Capacity) => token_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "The signer has reached its session capacity.",
        ),
    }
}

#[derive(Deserialize)]
pub struct RevocationRequest {
    token: String,
}

/// OAuth 2.0 token revocation (RFC 7009). Revoking either the access or the
/// refresh token ends that whole login. Unknown tokens also answer 200.
pub async fn oauth_revoke(
    State(state): State<AppState>,
    form: Result<Form<RevocationRequest>, FormRejection>,
) -> Response {
    let request_id = Ulid::new().to_string();
    let Ok(Form(request)) = form else {
        return token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "The revocation request must be form-encoded and contain a token.",
        );
    };
    let token = Zeroizing::new(request.token);
    if let Some(account) = state.auth.revoke_session(&token) {
        audit_login(&request_id, "oauth-logout", true, "ok", Some(&account));
    }
    no_store(StatusCode::OK)
}

/// Redirect a browser. The URL carries one-time credentials in its query, so
/// keep it out of caches and out of any Referer header.
fn browser_redirect(status: StatusCode, location: &reqwest::Url) -> Response {
    let Ok(location) = HeaderValue::from_str(location.as_str()) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let mut response = no_store(status);
    let headers = response.headers_mut();
    headers.insert(LOCATION, location);
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    response
}

fn no_store(response: impl IntoResponse) -> Response {
    let mut response = response.into_response();
    let headers = response.headers_mut();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

/// RFC 6749 section 4.1.2.1 error code reported to the CLI's redirect URI.
fn oauth_redirect_error_code(error: &OAuthFlowError) -> &'static str {
    match error {
        OAuthFlowError::AuthorizationDenied
        | OAuthFlowError::CodeExchangeFailed
        | OAuthFlowError::ScopeNotGranted
        | OAuthFlowError::ClaimsDenied
        | OAuthFlowError::TwoFactorRequired => "access_denied",
        OAuthFlowError::IdentityProviderUnavailable | OAuthFlowError::Capacity => {
            "temporarily_unavailable"
        }
        OAuthFlowError::TokenRevocationFailed => "server_error",
    }
}

fn audit_login(
    request_id: &str,
    operation: &str,
    success: bool,
    reason: &str,
    account: Option<&Account>,
) {
    let identity_id = account.map_or("", |account| account.identity_id.as_str());
    let github_user_id = account.map_or("", |account| account.user_id.as_str());
    let github_login = account.map_or("", |account| account.login.as_str());
    if success {
        tracing::info!(
            target: "microtun_signer::audit",
            request_id, operation, success, reason, identity_id, github_user_id, github_login,
            "microtun signer login audit event"
        );
    } else {
        tracing::warn!(
            target: "microtun_signer::audit",
            request_id, operation, success, reason, identity_id, github_user_id, github_login,
            "microtun signer login audit event"
        );
    }
}

pub async fn get_public_key(
    State(state): State<AppState>,
    Path(key_id): Path<String>,
) -> Result<Response, ApiError> {
    let request_id = Ulid::new().to_string();
    let key = if valid_key_id(&key_id) {
        state.keys.get(&key_id)
    } else {
        None
    }
    .ok_or_else(|| {
        ApiError::new(
            StatusCode::NOT_FOUND,
            "unknown-key",
            "Unknown signing key",
            "The requested immutable signing key identifier does not exist.",
            &request_id,
        )
    })?;

    let pem = key.public_key_pem().ok_or_else(|| {
        ApiError::new(
            StatusCode::LOCKED,
            "key-locked",
            "Signing key is locked",
            "The public key becomes available after the signing key is unlocked.",
            &request_id,
        )
    })?;

    Ok(([(CONTENT_TYPE, "application/x-pem-file")], pem).into_response())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnlockRequest {
    passphrase: String,
}

pub async fn unlock_key(
    State(state): State<AdminState>,
    Path(key_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let request_id = Ulid::new().to_string();

    require_json_unlock_request(&headers, &request_id)?;

    let key = if valid_key_id(&key_id) {
        state.keys.get(&key_id)
    } else {
        None
    };
    let Some(key) = key else {
        tracing::warn!(
            target: "microtun_signer::audit",
            request_id = %request_id,
            operation = "unlock-key",
            success = false,
            reason = "unknown-key",
            key_id = %key_id,
            "microtun signer unlock audit event"
        );
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "unknown-key",
            "Unknown signing key",
            "The requested immutable signing key identifier does not exist.",
            &request_id,
        ));
    };

    let passphrase = parse_unlock_request(&body, &request_id)?;

    // The KDF takes hundreds of milliseconds to seconds of CPU, so it runs on
    // the blocking pool instead of stalling a runtime worker. The permit is
    // moved into the blocking task: if the client disconnects, the permit is
    // still held until the decryption actually finishes.
    let permit = state
        .unlock_permits
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| unlock_task_failed(&request_id, key.id()))?;
    let keys = state.keys.clone();
    let blocking_key_id = key.id().to_owned();
    let unlock_result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        keys.get(&blocking_key_id)
            .expect("key existence was checked before spawning")
            .unlock(passphrase.as_str())
    })
    .await
    .map_err(|_| unlock_task_failed(&request_id, key.id()))?;

    let outcome = match unlock_result {
        Ok(outcome) => outcome,
        Err(UnlockError::Inactive) => {
            tracing::warn!(
                target: "microtun_signer::audit",
                request_id = %request_id,
                operation = "unlock-key",
                success = false,
                reason = "key-not-active",
                key_id = key.id(),
                "microtun signer unlock audit event"
            );
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "key-state-conflict",
                "Signing key is not active",
                "Only active signing keys can be unlocked.",
                &request_id,
            ));
        }
        Err(UnlockError::InvalidPassphrase) => {
            tracing::warn!(
                target: "microtun_signer::audit",
                request_id = %request_id,
                operation = "unlock-key",
                success = false,
                reason = "invalid-passphrase",
                key_id = key.id(),
                "microtun signer unlock audit event"
            );
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "invalid-key-passphrase",
                "Signing key unlock failed",
                "The supplied passphrase could not unlock the encrypted signing key.",
                &request_id,
            ));
        }
        Err(UnlockError::LockPoisoned) => {
            return Err(ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "key-lock-failure",
                "Signing key lock failed",
                "The signing key could not be unlocked due to an internal state error.",
                &request_id,
            ));
        }
    };

    tracing::info!(
        target: "microtun_signer::audit",
        request_id = %request_id,
        operation = "unlock-key",
        success = true,
        reason = if outcome == UnlockOutcome::AlreadyUnlocked { "already-unlocked" } else { "ok" },
        key_id = key.id(),
        "microtun signer unlock audit event"
    );

    Ok(StatusCode::NO_CONTENT)
}

fn require_json_unlock_request(headers: &HeaderMap, request_id: &str) -> Result<(), ApiError> {
    if is_json_content_type(headers) {
        return Ok(());
    }
    Err(ApiError::new(
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "unsupported-content-type",
        "Unsupported content type",
        "Unlock requests must use Content-Type: application/json.",
        request_id,
    ))
}

fn parse_unlock_request(body: &[u8], request_id: &str) -> Result<Zeroizing<String>, ApiError> {
    let request: UnlockRequest = serde_json::from_slice(body).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "malformed-json",
            "Malformed unlock request",
            "The request body must contain a JSON string field named passphrase.",
            request_id,
        )
    })?;
    let passphrase = Zeroizing::new(request.passphrase);
    if passphrase.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "empty-passphrase",
            "Signing key passphrase is empty",
            "The unlock passphrase must not be empty.",
            request_id,
        ));
    }
    Ok(passphrase)
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyringUnlockResponse {
    pub keyring: String,
    pub keys: Vec<KeyringUnlockKey>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyringUnlockKey {
    pub key_id: String,
    pub result: String,
}

impl From<&KeyringMemberOutcome> for KeyringUnlockKey {
    fn from(outcome: &KeyringMemberOutcome) -> Self {
        Self {
            key_id: outcome.key_id.clone(),
            result: outcome.result.as_str().to_owned(),
        }
    }
}

/// Unlock every active key in a configured keyring with one passphrase.
///
/// All locked members are decrypted before any of them is unlocked, so a
/// passphrase that does not open every member leaves the keyring locked.
pub async fn unlock_keyring(
    State(state): State<AdminState>,
    Path(keyring): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<KeyringUnlockResponse>, ApiError> {
    let request_id = Ulid::new().to_string();
    require_json_unlock_request(&headers, &request_id)?;

    if !valid_keyring_name(&keyring) || !state.keys.has_keyring(&keyring) {
        keyring_audit_failure(&request_id, &keyring, "unknown-keyring", &[]);
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "unknown-keyring",
            "Unknown keyring",
            "No configured signing key belongs to the requested keyring.",
            &request_id,
        ));
    }

    let passphrase = parse_unlock_request(&body, &request_id)?;

    // Same reasoning as unlock_key: one KDF at a time, off the runtime, with
    // the permit held until the blocking work really finishes.
    let permit = state
        .unlock_permits
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| keyring_unlock_task_failed(&request_id, &keyring))?;
    let keys = state.keys.clone();
    let blocking_keyring = keyring.clone();
    let unlock_result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        keys.unlock_keyring(&blocking_keyring, passphrase.as_str())
    })
    .await
    .map_err(|_| keyring_unlock_task_failed(&request_id, &keyring))?;

    let outcomes = match unlock_result {
        Ok(outcomes) => outcomes,
        Err(KeyringUnlockError::UnknownKeyring) => {
            keyring_audit_failure(&request_id, &keyring, "unknown-keyring", &[]);
            return Err(ApiError::new(
                StatusCode::NOT_FOUND,
                "unknown-keyring",
                "Unknown keyring",
                "No configured signing key belongs to the requested keyring.",
                &request_id,
            ));
        }
        Err(KeyringUnlockError::NoActiveKeys) => {
            keyring_audit_failure(&request_id, &keyring, "no-active-keys", &[]);
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "keyring-has-no-active-keys",
                "Keyring has no active keys",
                "Only active signing keys can be unlocked, and this keyring has none.",
                &request_id,
            ));
        }
        Err(KeyringUnlockError::InvalidPassphrase) => {
            keyring_audit_failure(&request_id, &keyring, "invalid-passphrase", &[]);
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "invalid-key-passphrase",
                "Keyring unlock failed",
                "The supplied passphrase did not unlock any key in the keyring.",
                &request_id,
            ));
        }
        Err(KeyringUnlockError::PassphraseMismatch { failed, .. }) => {
            keyring_audit_failure(
                &request_id,
                &keyring,
                "keyring-passphrase-mismatch",
                &failed,
            );
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "keyring-passphrase-mismatch",
                "Keyring passphrase mismatch",
                "The passphrase unlocked some keys in the keyring but not others, so none were unlocked.",
                &request_id,
            )
            .with_keys(failed));
        }
        Err(KeyringUnlockError::LockPoisoned) => {
            return Err(ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "key-lock-failure",
                "Signing key lock failed",
                "The keyring could not be unlocked due to an internal state error.",
                &request_id,
            ));
        }
    };

    for outcome in &outcomes {
        tracing::info!(
            target: "microtun_signer::audit",
            request_id = %request_id,
            operation = "unlock-keyring",
            success = true,
            reason = outcome.result.as_str(),
            keyring = %keyring,
            key_id = %outcome.key_id,
            "microtun signer unlock audit event"
        );
    }

    Ok(Json(KeyringUnlockResponse {
        keys: outcomes.iter().map(KeyringUnlockKey::from).collect(),
        keyring,
    }))
}

fn keyring_audit_failure(request_id: &str, keyring: &str, reason: &str, failed_keys: &[String]) {
    tracing::warn!(
        target: "microtun_signer::audit",
        request_id = %request_id,
        operation = "unlock-keyring",
        success = false,
        reason = reason,
        keyring = %keyring,
        failed_key_ids = ?failed_keys,
        "microtun signer unlock audit event"
    );
}

fn keyring_unlock_task_failed(request_id: &str, keyring: &str) -> ApiError {
    tracing::error!(
        target: "microtun_signer::audit",
        request_id = %request_id,
        operation = "unlock-keyring",
        success = false,
        reason = "unlock-task-failed",
        keyring = %keyring,
        "microtun signer unlock audit event"
    );
    ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "key-unlock-failure",
        "Keyring unlock failed",
        "The keyring could not be unlocked due to an internal error.",
        request_id,
    )
}

fn unlock_task_failed(request_id: &str, key_id: &str) -> ApiError {
    tracing::error!(
        target: "microtun_signer::audit",
        request_id = %request_id,
        operation = "unlock-key",
        success = false,
        reason = "unlock-task-failed",
        key_id = key_id,
        "microtun signer unlock audit event"
    );
    ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "key-unlock-failure",
        "Signing key unlock failed",
        "The signing key could not be unlocked due to an internal error.",
        request_id,
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningRequest {
    digest: String,
}

#[derive(Serialize)]
pub struct SignatureResponse {
    signature: String,
}

pub async fn create_signature(
    State(state): State<AppState>,
    Path(key_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<SignatureResponse>, ApiError> {
    let attempt_request_id = Ulid::new().to_string();

    if !is_json_content_type(&headers) {
        return Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-content-type",
            "Unsupported content type",
            "Signing requests must use Content-Type: application/json.",
            &attempt_request_id,
        ));
    }

    let principal = match state.auth.authenticate(&headers).await {
        Ok(principal) => principal,
        Err(error) => {
            let api_error = auth_error(error, &attempt_request_id);
            audit_best_effort(
                &state,
                AuditRecord {
                    request_id: attempt_request_id.clone(),
                    operation: "sign".into(),
                    success: false,
                    reason: api_error.slug.to_owned(),
                    ..AuditRecord::default()
                },
            )
            .await;
            return Err(api_error);
        }
    };

    let request: SigningRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => {
            let error = ApiError::new(
                StatusCode::BAD_REQUEST,
                "malformed-json",
                "Malformed signing request",
                "The request body must contain exactly one base64-encoded SHA-256 digest.",
                &attempt_request_id,
            );
            audit_best_effort(
                &state,
                audit_record(
                    &attempt_request_id,
                    "sign",
                    false,
                    error.slug,
                    Some(&principal),
                    AuditDetails {
                        key_id: Some(&key_id),
                        ..AuditDetails::default()
                    },
                ),
            )
            .await;
            return Err(error);
        }
    };

    let digest = match validate_signing_request(&state, &principal, &key_id, request) {
        Ok(digest) => digest,
        Err(mut error) => {
            error.request_id = attempt_request_id.clone();
            audit_best_effort(
                &state,
                audit_record(
                    &attempt_request_id,
                    "sign",
                    false,
                    error.slug,
                    Some(&principal),
                    AuditDetails {
                        key_id: Some(&key_id),
                        ..AuditDetails::default()
                    },
                ),
            )
            .await;
            return Err(error);
        }
    };

    let key = state
        .keys
        .get(&key_id)
        .expect("validated key must remain present in immutable keyring");
    let firmware_digest = hex::encode(digest);
    let signature = match key.sign_digest(&digest) {
        Ok(signature) => signature,
        Err(SignError::Locked) => {
            return Err(ApiError::new(
                StatusCode::LOCKED,
                "key-locked",
                "Signing key is locked",
                "The requested signing key must be manually unlocked before it can create signatures.",
                &attempt_request_id,
            ));
        }
        Err(SignError::Failed) => {
            return Err(ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "signing-failed",
                "Signing operation failed",
                "The signing key could not create a signature due to an internal error.",
                &attempt_request_id,
            ));
        }
    };

    audit_best_effort(
        &state,
        audit_record(
            &attempt_request_id,
            "sign",
            true,
            "ok",
            Some(&principal),
            AuditDetails {
                key_id: Some(&key_id),
                firmware_digest: Some(&firmware_digest),
            },
        ),
    )
    .await;

    Ok(Json(SignatureResponse {
        signature: BASE64.encode(signature),
    }))
}

fn validate_signing_request(
    state: &AppState,
    principal: &AuthPrincipal,
    key_id: &str,
    request: SigningRequest,
) -> Result<[u8; 32], ApiError> {
    if !valid_key_id(key_id) {
        return Err(unknown_key_error());
    }
    state
        .authz
        .authorize(principal, PolicyAction::Sign, key_id)
        .map_err(|_| policy_denied_error())?;

    let Some(key) = state.keys.get(key_id) else {
        return Err(unknown_key_error());
    };
    if key.state() != KeyState::Active {
        return Err(ApiError::without_request_id(
            StatusCode::CONFLICT,
            "key-state-conflict",
            "Signing key is not active",
            "The requested key is available for metadata lookup but cannot create new signatures.",
        ));
    }
    if !key.is_unlocked() {
        return Err(ApiError::without_request_id(
            StatusCode::LOCKED,
            "key-locked",
            "Signing key is locked",
            "The requested signing key must be manually unlocked before it can create signatures.",
        ));
    }

    let decoded = BASE64.decode(request.digest.as_bytes()).map_err(|_| {
        ApiError::unprocessable(
            "invalid-digest-base64",
            "Invalid firmware digest",
            "digest must be valid base64.",
        )
    })?;
    let digest: [u8; 32] = decoded.try_into().map_err(|bytes: Vec<u8>| {
        ApiError::unprocessable(
            "invalid-digest-length",
            "Invalid firmware digest length",
            if bytes.len() < 32 {
                "The decoded SHA-256 digest is shorter than 32 bytes."
            } else {
                "The decoded SHA-256 digest is longer than 32 bytes."
            },
        )
    })?;

    validate_signing_context(principal)?;
    Ok(digest)
}

fn unknown_key_error() -> ApiError {
    ApiError::without_request_id(
        StatusCode::NOT_FOUND,
        "unknown-key",
        "Unknown signing key",
        "The requested immutable signing key identifier does not exist.",
    )
}

fn validate_signing_context(principal: &AuthPrincipal) -> Result<(), ApiError> {
    let AuthSource::GithubActions(actions) = &principal.source else {
        return Ok(());
    };

    if actions.ref_type != "tag" {
        return Err(ApiError::without_request_id(
            StatusCode::FORBIDDEN,
            "tag-required",
            "A release tag is required",
            "Firmware signing from GitHub Actions requires an authenticated tag ref.",
        ));
    }

    // Anyone who can push a tag controls the workflow file at that tag. Only
    // accept tags that GitHub reports as protected by a ruleset, so that
    // creating a release tag is itself a privileged operation.
    if !actions.ref_protected {
        return Err(ApiError::without_request_id(
            StatusCode::FORBIDDEN,
            "protected-ref-required",
            "A protected release tag is required",
            "Firmware signing from GitHub Actions requires a tag protected by a GitHub ruleset.",
        ));
    }

    let Some(tag) = actions.git_ref.strip_prefix("refs/tags/") else {
        return Err(ApiError::without_request_id(
            StatusCode::FORBIDDEN,
            "tag-required",
            "A release tag is required",
            "The authenticated GitHub Actions ref must be under refs/tags/.",
        ));
    };
    if tag.is_empty() {
        return Err(ApiError::without_request_id(
            StatusCode::FORBIDDEN,
            "tag-required",
            "A release tag is required",
            "The authenticated GitHub Actions tag ref must name a tag.",
        ));
    }

    Ok(())
}

fn is_json_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
}

fn auth_error(error: AuthError, request_id: &str) -> ApiError {
    match error {
        AuthError::ClaimsDenied => ApiError::new(
            StatusCode::FORBIDDEN,
            "identity-not-authorized",
            "Authenticated identity is not authorized",
            "The authenticated GitHub identity does not satisfy the signer requirements.",
            request_id,
        ),
        AuthError::KeyDiscovery => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "oidc-key-discovery-unavailable",
            "OIDC verification is temporarily unavailable",
            "The signer could not refresh the GitHub Actions OIDC verification keys.",
            request_id,
        ),
        AuthError::IdentityProviderUnavailable => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "identity-provider-unavailable",
            "GitHub identity verification is temporarily unavailable",
            "The signer could not verify the GitHub account credential.",
            request_id,
        ),
        AuthError::ReplayCacheUnavailable => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "oidc-replay-cache-unavailable",
            "OIDC replay protection is temporarily unavailable",
            "The signer could not record the GitHub Actions token as used.",
            request_id,
        ),
        AuthError::TokenReplayed => {
            let mut error = ApiError::unauthorized(request_id);
            error.slug = "token-replayed";
            error
        }
        AuthError::MissingBearer | AuthError::TokenTooLarge | AuthError::InvalidToken => {
            ApiError::unauthorized(request_id)
        }
    }
}

fn policy_denied_error() -> ApiError {
    ApiError::without_request_id(
        StatusCode::FORBIDDEN,
        "policy-denied",
        "Identity policy denied this operation",
        "The authenticated identity is not allowed to perform this action with the requested key.",
    )
}

#[derive(Default)]
struct AuditDetails<'a> {
    key_id: Option<&'a str>,
    firmware_digest: Option<&'a str>,
}

fn audit_record(
    request_id: &str,
    operation: &str,
    success: bool,
    reason: &str,
    principal: Option<&AuthPrincipal>,
    details: AuditDetails<'_>,
) -> AuditRecord {
    let account = principal.and_then(|principal| match &principal.source {
        AuthSource::GithubAccount(account) => Some(account),
        AuthSource::GithubActions(_) => None,
    });
    let actions = principal.and_then(|principal| match &principal.source {
        AuthSource::GithubAccount(_) => None,
        AuthSource::GithubActions(actions) => Some(actions),
    });
    AuditRecord {
        request_id: request_id.to_owned(),
        operation: operation.to_owned(),
        success,
        reason: reason.to_owned(),
        key_id: details.key_id.map(str::to_owned),
        firmware_digest: details.firmware_digest.map(str::to_owned),
        identity_id: principal.map(|principal| principal.identity_id.clone()),
        principal: principal.map(|principal| principal.principal_key.clone()),
        auth_method: principal.map(|principal| principal.auth_method.to_owned()),
        issuer: principal.map(|principal| principal.issuer.clone()),
        audience: principal.and_then(|principal| principal.audience.clone()),
        subject: principal.map(|principal| principal.subject.clone()),
        github_login: account.map(|identity| identity.login.clone()),
        github_user_id: account.map(|identity| identity.user_id.clone()),
        actor: actions.and_then(|identity| identity.actor.clone()),
        actor_id: actions.and_then(|identity| identity.actor_id.clone()),
        repository: actions.map(|identity| identity.repository.clone()),
        repository_id: actions.map(|identity| identity.repository_id.clone()),
        git_ref: actions.map(|identity| identity.git_ref.clone()),
        ref_protected: actions.map(|identity| identity.ref_protected),
        environment: actions.and_then(|identity| identity.environment.clone()),
        commit_sha: actions.map(|identity| identity.sha.clone()),
        event_name: actions.map(|identity| identity.event_name.clone()),
        workflow_ref: actions.map(|identity| identity.workflow_ref.clone()),
        run_id: actions.map(|identity| identity.run_id.clone()),
        run_attempt: actions.map(|identity| identity.run_attempt.clone()),
        jti: principal.and_then(|principal| principal.jti.clone()),
    }
}

async fn audit_best_effort(_state: &AppState, record: AuditRecord) {
    tracing::info!(
        target: "microtun_signer::audit",
        request_id = %record.request_id,
        operation = %record.operation,
        success = record.success,
        reason = %record.reason,
        key_id = record.key_id.as_deref().unwrap_or(""),
        firmware_digest = record.firmware_digest.as_deref().unwrap_or(""),
        identity_id = record.identity_id.as_deref().unwrap_or(""),
        principal = record.principal.as_deref().unwrap_or(""),
        auth_method = record.auth_method.as_deref().unwrap_or(""),
        issuer = record.issuer.as_deref().unwrap_or(""),
        audience = record.audience.as_deref().unwrap_or(""),
        subject = record.subject.as_deref().unwrap_or(""),
        github_login = record.github_login.as_deref().unwrap_or(""),
        github_user_id = record.github_user_id.as_deref().unwrap_or(""),
        actor = record.actor.as_deref().unwrap_or(""),
        actor_id = record.actor_id.as_deref().unwrap_or(""),
        repository = record.repository.as_deref().unwrap_or(""),
        repository_id = record.repository_id.as_deref().unwrap_or(""),
        git_ref = record.git_ref.as_deref().unwrap_or(""),
        ref_protected = record.ref_protected.unwrap_or(false),
        environment = record.environment.as_deref().unwrap_or(""),
        commit_sha = record.commit_sha.as_deref().unwrap_or(""),
        event_name = record.event_name.as_deref().unwrap_or(""),
        workflow_ref = record.workflow_ref.as_deref().unwrap_or(""),
        run_id = record.run_id.as_deref().unwrap_or(""),
        run_attempt = record.run_attempt.as_deref().unwrap_or(""),
        jti = record.jti.as_deref().unwrap_or(""),
        "microtun signer audit event"
    );
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: &'static str,
    request_id: String,
    /// Signing keys the error applies to, when it concerns specific keys.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    keys: Vec<String>,
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    slug: &'static str,
    request_id: String,
    authenticate: bool,
    keys: Vec<String>,
}

impl ApiError {
    fn new(
        status: StatusCode,
        slug: &'static str,
        _title: &'static str,
        _detail: &'static str,
        request_id: &str,
    ) -> Self {
        Self {
            status,
            slug,
            request_id: request_id.to_owned(),
            authenticate: false,
            keys: Vec::new(),
        }
    }

    fn with_keys(mut self, keys: Vec<String>) -> Self {
        self.keys = keys;
        self
    }

    fn without_request_id(
        status: StatusCode,
        slug: &'static str,
        title: &'static str,
        detail: &'static str,
    ) -> Self {
        Self::new(status, slug, title, detail, "")
    }

    fn unprocessable(slug: &'static str, title: &'static str, detail: &'static str) -> Self {
        Self::without_request_id(StatusCode::UNPROCESSABLE_ENTITY, slug, title, detail)
    }

    fn unauthorized(request_id: &str) -> Self {
        let mut error = Self::new(
            StatusCode::UNAUTHORIZED,
            "authentication-required",
            "Authentication required",
            "A signer OAuth session or GitHub Actions OIDC bearer credential is required.",
            request_id,
        );
        error.authenticate = true;
        error
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorBody {
            error: self.slug,
            request_id: self.request_id,
            keys: self.keys,
        };
        let mut response = (self.status, Json(body)).into_response();
        if self.authenticate {
            response.headers_mut().insert(
                WWW_AUTHENTICATE,
                "Bearer".parse().expect("valid authenticate header"),
            );
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthSource, GithubAccountIdentity, GithubActionsIdentity};

    #[test]
    fn confirmation_page_escapes_everything_taken_from_the_request() {
        let auth = Authenticator::for_tests();
        let state = r#""><script>alert(1)</script>&'"#;
        let request = AuthorizationRequest::new(
            "http://127.0.0.1:4000/callback",
            state,
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        )
        .unwrap();
        let page = confirmation_page(&auth, &request, "csrf-token");
        assert!(!page.contains("<script>"), "{page}");
        assert!(page.contains("&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;&amp;&#39;"));
        assert!(page.contains(&verification_code(&request.code_challenge)));
        assert!(page.contains("127.0.0.1:4000"));
        assert!(
            page.contains(r#"action="https://signer.example.com/v1/auth/authorize""#),
            "{page}"
        );
        // The style block is the one the Content-Security-Policy allows.
        assert!(page.contains(&format!("<style>{CONFIRMATION_PAGE_STYLE}</style>")));
        assert!(CONFIRMATION_PAGE_CSP.contains("frame-ancestors 'none'"));
        assert!(!CONFIRMATION_PAGE_CSP.contains("form-action"));
    }

    #[test]
    fn login_cookie_is_found_among_others_and_validated() {
        let token = new_browser_token();
        let mut headers = HeaderMap::new();
        assert_eq!(login_cookie(&headers, LOGIN_COOKIE_SECURE), None);
        headers.insert(
            COOKIE,
            format!("theme=dark; {LOGIN_COOKIE_SECURE}={token}; other=1")
                .parse()
                .unwrap(),
        );
        assert_eq!(login_cookie(&headers, LOGIN_COOKIE_SECURE), Some(token));
        // The development name is a different cookie.
        assert_eq!(login_cookie(&headers, LOGIN_COOKIE_INSECURE), None);

        headers.insert(
            COOKIE,
            format!("{LOGIN_COOKIE_SECURE}=not-a-token")
                .parse()
                .unwrap(),
        );
        assert_eq!(login_cookie(&headers, LOGIN_COOKIE_SECURE), None);
    }

    #[test]
    fn login_cookie_attributes_follow_the_public_url_scheme() {
        let token = new_browser_token();
        let https = set_login_cookie(&Authenticator::for_tests(), &token).unwrap();
        let https = https.to_str().unwrap();
        assert!(https.starts_with(&format!("__Host-mts-login={token}; Path=/;")));
        for attribute in ["HttpOnly", "SameSite=Lax", "Secure", "Max-Age=600"] {
            assert!(https.contains(attribute), "{https}");
        }

        let local = Authenticator::for_tests_with_github(
            "https://api.github.com",
            "http://127.0.0.1:8080",
            Vec::new(),
        );
        let http = set_login_cookie(&local, &token).unwrap();
        let http = http.to_str().unwrap();
        assert!(http.starts_with(&format!("mts-login={token}; ")), "{http}");
        assert!(!http.contains("Secure"), "{http}");
    }

    #[tokio::test]
    async fn version_reports_package_version() {
        let Json(response) = version().await;
        assert_eq!(response.version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn client_ip_prefers_the_last_hop_of_the_configured_header() {
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let header = HeaderName::from_static("x-forwarded-for");
        let mut headers = HeaderMap::new();
        assert_eq!(client_ip(Some(&header), &headers, Some(peer)), Some(peer));

        // The client claims 1.1.1.1; the proxy appended the address it saw.
        headers.insert(&header, "1.1.1.1, 203.0.113.7".parse().unwrap());
        let seen_by_proxy: IpAddr = "203.0.113.7".parse().unwrap();
        assert_eq!(
            client_ip(Some(&header), &headers, Some(peer)),
            Some(seen_by_proxy)
        );
        // Not configured: the header is client-controlled and ignored.
        assert_eq!(client_ip(None, &headers, Some(peer)), Some(peer));

        // A proxy that adds its own header line rather than appending.
        headers.append(&header, "2001:db8::1".parse().unwrap());
        assert_eq!(
            client_ip(Some(&header), &headers, Some(peer)),
            Some("2001:db8::1".parse().unwrap())
        );

        headers.insert(&header, "garbage".parse().unwrap());
        assert_eq!(client_ip(Some(&header), &headers, Some(peer)), Some(peer));
        assert_eq!(client_ip(Some(&header), &headers, None), None);
    }

    #[test]
    fn signing_request_accepts_only_digest() {
        let request: SigningRequest = serde_json::from_str(r#"{"digest":"AA=="}"#).unwrap();
        assert_eq!(request.digest, "AA==");
        assert!(
            serde_json::from_str::<SigningRequest>(r#"{"digest":"AA==","unexpected":"x"}"#)
                .is_err()
        );
    }

    fn actions_principal(git_ref: &str, ref_type: &str) -> AuthPrincipal {
        AuthPrincipal {
            identity_id: "release-actions".into(),
            principal_key: "github-actions:repository:123".into(),
            auth_method: "github-actions-oidc",
            issuer: "issuer".into(),
            audience: Some("aud".into()),
            subject: "subject".into(),
            jti: None,
            source: AuthSource::GithubActions(Box::new(GithubActionsIdentity {
                repository: "owner/repo".into(),
                repository_id: "123".into(),
                actor: Some("user".into()),
                actor_id: Some("456".into()),
                git_ref: git_ref.into(),
                ref_type: ref_type.into(),
                ref_protected: true,
                sha: "abcdef".into(),
                workflow_ref: "owner/repo/.github/workflows/release.yml@refs/tags/v1.2.3".into(),
                event_name: "push".into(),
                environment: Some("firmware-signing".into()),
                run_id: "42".into(),
                run_attempt: "1".into(),
            })),
        }
    }

    #[test]
    fn actions_signing_accepts_an_authenticated_tag_without_parsing_it_as_a_version() {
        let principal = actions_principal("refs/tags/release-candidate", "tag");
        assert!(validate_signing_context(&principal).is_ok());
    }

    #[test]
    fn actions_signing_requires_a_protected_tag() {
        let mut principal = actions_principal("refs/tags/v1.2.3", "tag");
        let AuthSource::GithubActions(actions) = &mut principal.source else {
            unreachable!()
        };
        actions.ref_protected = false;
        let error = validate_signing_context(&principal).unwrap_err();
        assert_eq!(error.slug, "protected-ref-required");
    }

    #[test]
    fn actions_signing_requires_an_authenticated_release_tag() {
        let principal = actions_principal("refs/heads/main", "branch");
        assert!(validate_signing_context(&principal).is_err());
    }

    #[test]
    fn human_signing_has_no_release_metadata_requirement() {
        let principal = AuthPrincipal {
            identity_id: "maintainer".into(),
            principal_key: "github-account:42".into(),
            auth_method: "github-oauth-session",
            issuer: "issuer".into(),
            audience: None,
            subject: "42".into(),
            jti: None,
            source: AuthSource::GithubAccount(GithubAccountIdentity {
                user_id: "42".into(),
                login: "octocat".into(),
            }),
        };

        assert!(validate_signing_context(&principal).is_ok());
    }

    fn admin_state() -> AdminState {
        let keys = KeyStore::from_keys_for_tests(vec![
            crate::key::KeyMaterial::from_pem_with_algorithm_for_tests(
                "prod",
                crate::config::KeyAlgorithm::P256,
                include_str!("../tests/fixtures/test-p256-scrypt.pem"),
            ),
        ]);
        AdminState::new(Arc::new(keys))
    }

    fn unlock_request(passphrase: &str) -> (HeaderMap, Bytes) {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let body = serde_json::to_vec(&serde_json::json!({ "passphrase": passphrase })).unwrap();
        (headers, Bytes::from(body))
    }

    /// On a single-threaded runtime, a KDF running inline would starve every
    /// other task until it finished. Here a ticker keeps running throughout.
    #[tokio::test(flavor = "current_thread")]
    async fn unlock_kdf_does_not_block_the_async_runtime() {
        let state = admin_state();
        let ticks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let ticker = {
            let ticks = ticks.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                    ticks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            })
        };

        let started = std::time::Instant::now();
        let (headers, body) = unlock_request("test-passphrase");
        let status = unlock_key(State(state.clone()), Path("prod".into()), headers, body)
            .await
            .unwrap();
        let elapsed = started.elapsed();
        ticker.abort();

        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(state.keys.get("prod").unwrap().is_unlocked());
        let ticks = ticks.load(std::sync::atomic::Ordering::Relaxed);
        // Expect roughly one tick per 5 ms of KDF time; demand at least a third.
        let expected = elapsed.as_millis() as usize / 15;
        assert!(
            ticks >= expected.max(1),
            "runtime starved: {ticks} ticks during {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn wrong_passphrase_is_rejected_through_the_blocking_path() {
        let state = admin_state();
        let (headers, body) = unlock_request("wrong");
        let error = unlock_key(State(state.clone()), Path("prod".into()), headers, body)
            .await
            .unwrap_err();
        assert_eq!(error.slug, "invalid-key-passphrase");
        assert!(!state.keys.get("prod").unwrap().is_unlocked());
        // The permit was released, so a later attempt can proceed.
        assert_eq!(state.unlock_permits.available_permits(), 1);
    }

    fn keyring_admin_state(second_pem: &str) -> AdminState {
        use crate::{config::KeyAlgorithm, key::KeyMaterial};
        let keys = KeyStore::from_keys_with_keyrings_for_tests(
            vec![
                KeyMaterial::from_pem_with_algorithm_for_tests(
                    "fw-a",
                    KeyAlgorithm::P256,
                    include_str!("../tests/fixtures/test-p256-scrypt.pem"),
                ),
                KeyMaterial::from_pem_with_algorithm_for_tests(
                    "fw-b",
                    KeyAlgorithm::P256,
                    second_pem,
                ),
            ],
            &[crate::config::KeyringConfig {
                id: "fw".into(),
                keys: vec!["fw-a".into(), "fw-b".into()],
            }],
        );
        AdminState::new(Arc::new(keys))
    }

    #[tokio::test]
    async fn keyring_unlock_reports_each_key() {
        let state =
            keyring_admin_state(include_str!("../tests/fixtures/test-p256-pbkdf2-600k.pem"));
        let (headers, body) = unlock_request("test-passphrase");
        let Json(response) = unlock_keyring(State(state.clone()), Path("fw".into()), headers, body)
            .await
            .unwrap();
        assert_eq!(response.keyring, "fw");
        let keys: Vec<_> = response
            .keys
            .iter()
            .map(|k| (k.key_id.as_str(), k.result.as_str()))
            .collect();
        assert_eq!(keys, [("fw-a", "unlocked"), ("fw-b", "unlocked")]);
        assert!(state.keys.iter().all(|key| key.is_unlocked()));
        assert_eq!(state.unlock_permits.available_permits(), 1);
    }

    #[tokio::test]
    async fn keyring_mismatch_names_failed_keys_and_unlocks_nothing() {
        // fw-b is a secp256k1 key configured as p256, so the shared
        // passphrase cannot open it.
        let state =
            keyring_admin_state(include_str!("../tests/fixtures/test-secp256k1-scrypt.pem"));
        let (headers, body) = unlock_request("test-passphrase");
        let error = unlock_keyring(State(state.clone()), Path("fw".into()), headers, body)
            .await
            .unwrap_err();
        assert_eq!(error.slug, "keyring-passphrase-mismatch");
        assert_eq!(error.keys, ["fw-b"]);
        assert!(state.keys.iter().all(|key| !key.is_unlocked()));

        let response = error.into_response();
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["keys"], serde_json::json!(["fw-b"]));
    }

    #[tokio::test]
    async fn unknown_keyring_is_rejected_before_reading_the_passphrase() {
        let state =
            keyring_admin_state(include_str!("../tests/fixtures/test-p256-pbkdf2-600k.pem"));
        for name in ["missing", "bad/name", "fw-a"] {
            let (headers, body) = unlock_request("test-passphrase");
            let error = unlock_keyring(State(state.clone()), Path(name.into()), headers, body)
                .await
                .unwrap_err();
            assert_eq!(error.slug, "unknown-keyring", "{name}");
        }
        assert!(state.keys.iter().all(|key| !key.is_unlocked()));
    }
}
