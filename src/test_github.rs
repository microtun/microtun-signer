//! A minimal stand-in for github.com and api.github.com, for tests only.

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use axum::{
    Form, Json, Router,
    extract::{Query, State},
    http::{StatusCode, header::LOCATION},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use serde_json::json;
use sha2::{Digest, Sha256};

const CODE_PREFIX: &str = "ghcode_";

#[derive(Clone)]
pub struct MockGithub {
    /// What the user does on GitHub's consent screen.
    pub user_approves: bool,
    pub exchange_status: StatusCode,
    pub scope: String,
    pub user_status: StatusCode,
    pub user_id: u64,
    pub login: String,
    pub two_factor_authentication: Option<bool>,
    pub revoke_status: StatusCode,
    pub exchanges: Arc<AtomicUsize>,
    pub revocations: Arc<AtomicUsize>,
}

impl Default for MockGithub {
    fn default() -> Self {
        Self {
            user_approves: true,
            exchange_status: StatusCode::OK,
            scope: "read:user".into(),
            user_status: StatusCode::OK,
            user_id: 42,
            login: "octocat".into(),
            two_factor_authentication: Some(true),
            revoke_status: StatusCode::NO_CONTENT,
            exchanges: Arc::new(AtomicUsize::new(0)),
            revocations: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl MockGithub {
    pub fn exchanges(&self) -> usize {
        self.exchanges.load(Ordering::SeqCst)
    }

    pub fn revocations(&self) -> usize {
        self.revocations.load(Ordering::SeqCst)
    }

    /// Serve the mock on an ephemeral loopback port and return its base URL.
    pub async fn spawn(self) -> (String, tokio::task::JoinHandle<()>) {
        let app = Router::new()
            .route("/login/oauth/authorize", get(authorize))
            .route("/login/oauth/access_token", post(access_token))
            .route(
                "/applications/{client_id}/token",
                axum::routing::delete(revoke),
            )
            .route("/user", get(user))
            .with_state(self);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), task)
    }
}

/// The authorization code the mock hands out for an authorize URL. It embeds
/// the PKCE challenge so the token endpoint can verify the verifier.
pub fn code_for_authorize_url(url: &reqwest::Url) -> String {
    let challenge = url
        .query_pairs()
        .find(|(key, _)| key == "code_challenge")
        .map(|(_, value)| value.into_owned())
        .unwrap_or_default();
    format!("{CODE_PREFIX}{challenge}")
}

pub fn query_param(url: &reqwest::Url, name: &str) -> Option<String> {
    url.query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

/// The consent screen: an already-authorized app is redirected straight back.
async fn authorize(
    State(state): State<MockGithub>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let required = [
        "client_id",
        "redirect_uri",
        "scope",
        "state",
        "code_challenge",
    ];
    if required.iter().any(|name| !params.contains_key(*name))
        || params["client_id"] != "Iv1.test"
        || params["scope"] != "read:user"
        || params.get("code_challenge_method").map(String::as_str) != Some("S256")
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let mut redirect = reqwest::Url::parse(&params["redirect_uri"]).unwrap();
    if state.user_approves {
        redirect.query_pairs_mut().append_pair(
            "code",
            &format!("{CODE_PREFIX}{}", params["code_challenge"]),
        );
    } else {
        redirect
            .query_pairs_mut()
            .append_pair("error", "access_denied");
    }
    redirect
        .query_pairs_mut()
        .append_pair("state", &params["state"]);
    (StatusCode::FOUND, [(LOCATION, redirect.to_string())]).into_response()
}

async fn access_token(
    State(state): State<MockGithub>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    state.exchanges.fetch_add(1, Ordering::SeqCst);
    if state.exchange_status != StatusCode::OK {
        return state.exchange_status.into_response();
    }
    let field = |name: &str| form.get(name).map(String::as_str).unwrap_or_default();
    if field("client_id") != "Iv1.test" || field("client_secret") != "secret" {
        return Json(json!({ "error": "incorrect_client_credentials" })).into_response();
    }
    let expected_challenge = B64URL.encode(Sha256::digest(field("code_verifier").as_bytes()));
    if field("code").strip_prefix(CODE_PREFIX) != Some(expected_challenge.as_str())
        || !field("redirect_uri").ends_with("/v1/auth/github/callback")
    {
        // Like the real thing, errors come back with HTTP 200.
        return Json(json!({ "error": "bad_verification_code" })).into_response();
    }
    Json(json!({
        "access_token": "gho_mock",
        "token_type": "bearer",
        "scope": state.scope,
    }))
    .into_response()
}

async fn user(State(state): State<MockGithub>) -> Response {
    if state.user_status != StatusCode::OK {
        return state.user_status.into_response();
    }
    Json(json!({
        "login": state.login,
        "id": state.user_id,
        "two_factor_authentication": state.two_factor_authentication,
    }))
    .into_response()
}

async fn revoke(State(state): State<MockGithub>) -> Response {
    state.revocations.fetch_add(1, Ordering::SeqCst);
    state.revoke_status.into_response()
}

/// What a browser keeps from the signer's confirmation page.
pub struct ConfirmationPage {
    /// `name=value` of the login cookie the page set.
    pub cookie: String,
    pub action: String,
    pub fields: Vec<(String, String)>,
}

fn html_unescape(value: &str) -> String {
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

fn attribute(tag: &str, name: &str) -> Option<String> {
    let start = tag.find(&format!("{name}=\""))? + name.len() + 2;
    let end = start + tag[start..].find('"')?;
    Some(html_unescape(&tag[start..end]))
}

/// A client that, like a browser being observed step by step, follows no
/// redirect on its own.
pub fn browser_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

/// Open the signer's authorization URL and read the confirmation page.
pub async fn open_confirmation_page(authorize_url: &reqwest::Url) -> ConfirmationPage {
    let response = browser_client()
        .get(authorize_url.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let html = response.text().await.unwrap();
    let form = &html[html.find("<form ").expect("the page has a form")..];
    let action = attribute(form, "action").unwrap();
    let fields = form
        .split("<input ")
        .skip(1)
        .map(|input| {
            (
                attribute(input, "name").unwrap(),
                attribute(input, "value").unwrap(),
            )
        })
        .collect();
    ConfirmationPage {
        cookie,
        action,
        fields,
    }
}

/// Press the button on the confirmation page. `cookie` and `origin` are what
/// the browser would send along; tests leave them out or change them to play
/// a request that did not come from the signer's own page.
pub async fn submit_confirmation(
    page: &ConfirmationPage,
    cookie: Option<&str>,
    origin: Option<&str>,
) -> reqwest::Response {
    let mut request = browser_client().post(&page.action).form(&page.fields);
    if let Some(cookie) = cookie {
        request = request.header("cookie", cookie);
    }
    if let Some(origin) = origin {
        request = request.header("origin", origin);
    }
    request.send().await.unwrap()
}

/// Follow redirects from `response` to the end, sending `cookie` only to the
/// signer (`signer_origin`), as a browser's cookie jar would.
pub async fn follow_redirects(
    mut response: reqwest::Response,
    signer_origin: &str,
    cookie: Option<&str>,
) -> reqwest::Response {
    while response.status().is_redirection() {
        let location = reqwest::Url::parse(response.headers()[LOCATION].to_str().unwrap()).unwrap();
        let mut request = browser_client().get(location.clone());
        if let Some(cookie) = cookie
            && location.origin().ascii_serialization() == signer_origin
        {
            request = request.header("cookie", cookie);
        }
        response = request.send().await.unwrap();
    }
    response
}

/// Stands in for a person at a browser: opens the confirmation page, presses
/// the button, and follows signer -> GitHub -> signer -> CLI loopback
/// listener. Returns the last page.
pub async fn browser_sign_in(authorize_url: &reqwest::Url) -> reqwest::Response {
    let origin = authorize_url.origin().ascii_serialization();
    let page = open_confirmation_page(authorize_url).await;
    let submitted = submit_confirmation(&page, Some(&page.cookie), Some(&origin)).await;
    assert_eq!(submitted.status(), StatusCode::SEE_OTHER);
    follow_redirects(submitted, &origin, Some(&page.cookie)).await
}
