//! In-memory state for the signer's own OAuth 2.0 authorization server.
//!
//! The CLI is a public OAuth client of the signer: it runs the authorization
//! code flow with PKCE (RFC 7636) against a loopback redirect URI (RFC 8252)
//! and receives signer-local access and refresh tokens. The signer in turn is
//! a confidential OAuth client of GitHub, which is only used to prove who the
//! user is. GitHub credentials never reach the CLI.
//!
//! Everything here lives in process memory only, so restarting the service
//! ends every login. Raw tokens and codes are never stored, only their
//! SHA-256 digests.

use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use sha2::{Digest, Sha256};

/// The only OAuth client the signer knows: its own command-line interface.
/// It is a public client, so there is no client secret.
pub const CLI_CLIENT_ID: &str = "microtun-signer-cli";
pub const ACCESS_TOKEN_PREFIX: &str = "mts_";
pub const REFRESH_TOKEN_PREFIX: &str = "mtr_";
const AUTHORIZATION_CODE_PREFIX: &str = "mtc_";

/// How long a user has to get through GitHub's consent screen.
const PENDING_LOGIN_TTL: Duration = Duration::from_secs(10 * 60);
/// The CLI redeems the code immediately after the browser redirect.
const AUTHORIZATION_CODE_TTL: Duration = Duration::from_secs(60);
const MAX_PENDING_LOGINS: usize = 1024;
const MAX_AUTHORIZATION_CODES: usize = 1024;
const MAX_GRANTS: usize = 4096;
/// Rotated-out refresh tokens remembered per login for reuse detection.
const MAX_RETIRED_REFRESH_TOKENS: usize = 32;
const MAX_STATE_BYTES: usize = 512;

type TokenKey = [u8; 32];

/// The authenticated GitHub account behind a login.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub identity_id: String,
    pub user_id: String,
    pub login: String,
}

/// Validated parameters of a CLI authorization request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationRequest {
    pub redirect_uri: String,
    pub state: String,
    pub code_challenge: String,
}

impl AuthorizationRequest {
    /// Accepts only loopback redirect URIs, so the signer can never be used
    /// as an open redirector or made to deliver a code to another host.
    pub fn new(
        redirect_uri: &str,
        state: &str,
        code_challenge: &str,
    ) -> Result<Self, &'static str> {
        if !valid_loopback_redirect_uri(redirect_uri) {
            return Err(
                "redirect_uri must be http://127.0.0.1:<port>/... or http://[::1]:<port>/...",
            );
        }
        if state.is_empty()
            || state.len() > MAX_STATE_BYTES
            || !state.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err("state must be 1-512 printable ASCII characters");
        }
        // An S256 challenge is the unpadded base64url encoding of 32 bytes.
        if code_challenge.len() != 43 || !code_challenge.bytes().all(is_base64url_byte) {
            return Err("code_challenge must be an S256 PKCE challenge");
        }
        Ok(Self {
            redirect_uri: redirect_uri.to_owned(),
            state: state.to_owned(),
            code_challenge: code_challenge.to_owned(),
        })
    }
}

/// A login waiting for the user to come back from GitHub.
#[derive(Clone, Debug)]
pub struct PendingLogin {
    pub request: AuthorizationRequest,
    /// PKCE verifier for the signer's own code exchange with GitHub.
    pub github_code_verifier: String,
    expires_at: Instant,
}

#[derive(Clone, Debug)]
pub struct TokenGrant {
    pub access_token: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum GrantError {
    /// Unknown, expired, already used, or mismatching code/token.
    Invalid,
    /// A rotated-out refresh token was presented again. The whole login has
    /// been revoked, because either the legitimate client or a thief now
    /// holds a token the other one used.
    RefreshTokenReused(Account),
    Capacity,
}

#[derive(Debug, PartialEq, Eq)]
pub struct CapacityError;

struct IssuedCode {
    request: AuthorizationRequest,
    account: Account,
    expires_at: Instant,
}

/// One login: everything issued from a single trip through GitHub.
struct Grant {
    account: Account,
    /// Absolute end of the login. Refreshing never extends it.
    deadline: Instant,
    access: Vec<(TokenKey, Instant)>,
    refresh_current: Option<TokenKey>,
    refresh_retired: VecDeque<TokenKey>,
}

#[derive(Default)]
struct Inner {
    pending: HashMap<TokenKey, PendingLogin>,
    codes: HashMap<TokenKey, IssuedCode>,
    grants: HashMap<u64, Grant>,
    /// Access token digest -> (grant, expiry).
    access: HashMap<TokenKey, (u64, Instant)>,
    /// Current and recently retired refresh token digests -> grant.
    refresh: HashMap<TokenKey, u64>,
    next_grant_id: u64,
}

pub struct OAuthStore {
    access_ttl: Duration,
    /// `None` disables refresh tokens: a login then lasts one access token.
    refresh_ttl: Option<Duration>,
    inner: Mutex<Inner>,
}

impl OAuthStore {
    pub fn new(access_ttl: Duration, refresh_ttl: Option<Duration>) -> Self {
        Self {
            access_ttl,
            refresh_ttl,
            inner: Mutex::new(Inner::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // No code path panics while holding the lock in a state worth
        // discarding, so a poisoned lock is still safe to use.
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Remember an authorization request and return the `state` value to send
    /// to GitHub together with the PKCE challenge for that leg.
    pub fn begin_login(
        &self,
        request: AuthorizationRequest,
    ) -> Result<(String, String), CapacityError> {
        let now = Instant::now();
        let mut inner = self.lock();
        inner.purge(now);
        if inner.pending.len() >= MAX_PENDING_LOGINS {
            return Err(CapacityError);
        }
        let state = B64URL.encode(random_bytes::<32>());
        let github_code_verifier = B64URL.encode(random_bytes::<32>());
        let github_code_challenge = s256(&github_code_verifier);
        inner.pending.insert(
            token_key(&state),
            PendingLogin {
                request,
                github_code_verifier,
                expires_at: now + PENDING_LOGIN_TTL,
            },
        );
        Ok((state, github_code_challenge))
    }

    /// Consume the pending login GitHub redirected back for. Single use.
    pub fn take_pending_login(&self, state: &str) -> Option<PendingLogin> {
        let now = Instant::now();
        self.lock()
            .pending
            .remove(&token_key(state))
            .filter(|pending| pending.expires_at > now)
    }

    /// Mint the one-time authorization code handed to the CLI through the
    /// browser redirect. It is bound to the CLI's redirect URI and PKCE
    /// challenge, so it is useless without the verifier only the CLI holds.
    pub fn issue_code(
        &self,
        request: &AuthorizationRequest,
        account: Account,
    ) -> Result<String, CapacityError> {
        let now = Instant::now();
        let mut inner = self.lock();
        inner.purge(now);
        if inner.codes.len() >= MAX_AUTHORIZATION_CODES {
            return Err(CapacityError);
        }
        let code = random_token(AUTHORIZATION_CODE_PREFIX);
        inner.codes.insert(
            token_key(&code),
            IssuedCode {
                request: request.clone(),
                account,
                expires_at: now + AUTHORIZATION_CODE_TTL,
            },
        );
        Ok(code)
    }

    /// `grant_type=authorization_code`. The code is consumed even when the
    /// redirect URI or PKCE verifier turn out to be wrong.
    pub fn redeem_code(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<(TokenGrant, Account), GrantError> {
        let now = Instant::now();
        let mut inner = self.lock();
        inner.purge(now);
        let issued = inner
            .codes
            .remove(&token_key(code))
            .filter(|issued| issued.expires_at > now)
            .ok_or(GrantError::Invalid)?;
        if issued.request.redirect_uri != redirect_uri
            || !valid_code_verifier(code_verifier)
            || s256(code_verifier) != issued.request.code_challenge
        {
            return Err(GrantError::Invalid);
        }
        if inner.grants.len() >= MAX_GRANTS {
            return Err(GrantError::Capacity);
        }

        let lifetime = self.refresh_ttl.unwrap_or(self.access_ttl);
        let id = inner.next_grant_id;
        inner.next_grant_id += 1;
        inner.grants.insert(
            id,
            Grant {
                account: issued.account.clone(),
                deadline: now + lifetime.max(self.access_ttl),
                access: Vec::new(),
                refresh_current: None,
                refresh_retired: VecDeque::new(),
            },
        );
        let tokens = inner.issue_tokens(id, now, self.access_ttl, self.refresh_ttl.is_some());
        Ok((tokens, issued.account))
    }

    /// `grant_type=refresh_token`. Refresh tokens rotate on every use; the
    /// access token already issued stays valid until its own expiry so that
    /// requests in flight are not cut off.
    pub fn refresh(&self, refresh_token: &str) -> Result<(TokenGrant, Account), GrantError> {
        if self.refresh_ttl.is_none() || !refresh_token.starts_with(REFRESH_TOKEN_PREFIX) {
            return Err(GrantError::Invalid);
        }
        let now = Instant::now();
        let key = token_key(refresh_token);
        let mut inner = self.lock();
        inner.purge(now);
        let id = *inner.refresh.get(&key).ok_or(GrantError::Invalid)?;
        let grant = inner.grants.get(&id).ok_or(GrantError::Invalid)?;
        let account = grant.account.clone();
        if grant.refresh_current != Some(key) {
            inner.remove_grant(id);
            return Err(GrantError::RefreshTokenReused(account));
        }
        let tokens = inner.issue_tokens(id, now, self.access_ttl, true);
        Ok((tokens, account))
    }

    /// End the login an access or refresh token belongs to (RFC 7009).
    pub fn revoke(&self, token: &str) -> Option<Account> {
        let key = token_key(token);
        let mut inner = self.lock();
        let id = inner
            .access
            .get(&key)
            .map(|(id, _)| *id)
            .or_else(|| inner.refresh.get(&key).copied())?;
        inner.remove_grant(id).map(|grant| grant.account)
    }

    /// Resolve a bearer access token presented to the signing API.
    pub fn authenticate(&self, access_token: &str) -> Option<Account> {
        if !access_token.starts_with(ACCESS_TOKEN_PREFIX) {
            return None;
        }
        let now = Instant::now();
        let inner = self.lock();
        let (id, expires_at) = inner.access.get(&token_key(access_token))?;
        if *expires_at <= now {
            return None;
        }
        inner.grants.get(id).map(|grant| grant.account.clone())
    }
}

impl Inner {
    fn purge(&mut self, now: Instant) {
        self.pending.retain(|_, pending| pending.expires_at > now);
        self.codes.retain(|_, issued| issued.expires_at > now);
        let expired: Vec<u64> = self
            .grants
            .iter()
            .filter(|(_, grant)| grant.deadline <= now)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            self.remove_grant(id);
        }
        self.access.retain(|_, (_, expires_at)| *expires_at > now);
    }

    fn remove_grant(&mut self, id: u64) -> Option<Grant> {
        let grant = self.grants.remove(&id)?;
        for (key, _) in &grant.access {
            self.access.remove(key);
        }
        for key in grant.refresh_current.iter().chain(&grant.refresh_retired) {
            self.refresh.remove(key);
        }
        Some(grant)
    }

    fn issue_tokens(
        &mut self,
        id: u64,
        now: Instant,
        access_ttl: Duration,
        with_refresh_token: bool,
    ) -> TokenGrant {
        let Self {
            grants,
            access,
            refresh,
            ..
        } = self;
        let grant = grants.get_mut(&id).expect("grant exists while locked");

        let expires_at = (now + access_ttl).min(grant.deadline);
        let access_token = random_token(ACCESS_TOKEN_PREFIX);
        let access_key = token_key(&access_token);
        grant.access.retain(|(_, expires_at)| *expires_at > now);
        grant.access.push((access_key, expires_at));
        access.insert(access_key, (id, expires_at));

        let refresh_token = with_refresh_token.then(|| {
            let token = random_token(REFRESH_TOKEN_PREFIX);
            let key = token_key(&token);
            if let Some(previous) = grant.refresh_current.replace(key) {
                grant.refresh_retired.push_back(previous);
                if grant.refresh_retired.len() > MAX_RETIRED_REFRESH_TOKENS
                    && let Some(forgotten) = grant.refresh_retired.pop_front()
                {
                    refresh.remove(&forgotten);
                }
            }
            refresh.insert(key, id);
            token
        });

        TokenGrant {
            access_token,
            expires_in: expires_at.saturating_duration_since(now).as_secs().max(1),
            refresh_token,
        }
    }
}

/// RFC 8252 section 7.3: loopback IP literal, any port, plain HTTP.
/// `localhost` is deliberately not accepted (section 8.3).
fn valid_loopback_redirect_uri(value: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(value) else {
        return false;
    };
    url.scheme() == "http"
        && matches!(url.host_str(), Some("127.0.0.1" | "[::1]"))
        && url.port().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
}

fn is_base64url_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
}

/// RFC 7636 section 4.1: 43-128 unreserved characters.
fn valid_code_verifier(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

fn s256(code_verifier: &str) -> String {
    B64URL.encode(Sha256::digest(code_verifier.as_bytes()))
}

fn random_token(prefix: &str) -> String {
    format!("{prefix}{}", B64URL.encode(random_bytes::<32>()))
}

/// Fill a fixed-size buffer from the operating system CSPRNG.
fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes).expect("operating system random number generator failed");
    bytes
}

fn token_key(token: &str) -> TokenKey {
    Sha256::digest(token.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const REDIRECT: &str = "http://127.0.0.1:49152/callback";

    fn store() -> OAuthStore {
        OAuthStore::new(
            Duration::from_secs(900),
            Some(Duration::from_secs(8 * 60 * 60)),
        )
    }

    fn account() -> Account {
        Account {
            identity_id: "maintainer".into(),
            user_id: "42".into(),
            login: "octocat".into(),
        }
    }

    fn request() -> AuthorizationRequest {
        AuthorizationRequest::new(REDIRECT, "client-state", &s256(VERIFIER)).unwrap()
    }

    fn login(store: &OAuthStore) -> TokenGrant {
        let code = store.issue_code(&request(), account()).unwrap();
        store.redeem_code(&code, REDIRECT, VERIFIER).unwrap().0
    }

    #[test]
    fn pkce_s256_matches_rfc_7636_appendix_b() {
        assert_eq!(
            s256(VERIFIER),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn only_loopback_redirect_uris_are_accepted() {
        let challenge = s256(VERIFIER);
        for accepted in [
            REDIRECT,
            "http://[::1]:8123/callback",
            "http://127.0.0.1:1/",
        ] {
            assert!(
                AuthorizationRequest::new(accepted, "s", &challenge).is_ok(),
                "{accepted}"
            );
        }
        for rejected in [
            "https://127.0.0.1:49152/callback",
            "http://127.0.0.1/callback",
            "http://localhost:49152/callback",
            "http://127.0.0.1.evil.example:49152/callback",
            "http://evil.example:49152/callback",
            "http://user@127.0.0.1:49152/callback",
            "http://127.0.0.1:49152/callback?x=1",
            "http://127.0.0.1:49152/callback#fragment",
            "not a url",
        ] {
            assert!(
                AuthorizationRequest::new(rejected, "s", &challenge).is_err(),
                "{rejected}"
            );
        }
    }

    #[test]
    fn state_and_challenge_are_validated() {
        let challenge = s256(VERIFIER);
        assert!(AuthorizationRequest::new(REDIRECT, "", &challenge).is_err());
        assert!(AuthorizationRequest::new(REDIRECT, "has space", &challenge).is_err());
        assert!(AuthorizationRequest::new(REDIRECT, &"a".repeat(513), &challenge).is_err());
        assert!(AuthorizationRequest::new(REDIRECT, "s", "too-short").is_err());
        assert!(AuthorizationRequest::new(REDIRECT, "s", &"=".repeat(43)).is_err());
    }

    #[test]
    fn pending_logins_are_single_use() {
        let store = store();
        let (state, github_challenge) = store.begin_login(request()).unwrap();
        let pending = store.take_pending_login(&state).unwrap();
        assert_eq!(pending.request, request());
        assert_eq!(s256(&pending.github_code_verifier), github_challenge);
        assert!(store.take_pending_login(&state).is_none());
        assert!(store.take_pending_login("unknown").is_none());
    }

    #[test]
    fn authorization_code_yields_tokens_once() {
        let store = store();
        let code = store.issue_code(&request(), account()).unwrap();
        let (tokens, who) = store.redeem_code(&code, REDIRECT, VERIFIER).unwrap();
        assert_eq!(who, account());
        assert!(tokens.access_token.starts_with(ACCESS_TOKEN_PREFIX));
        assert!(
            tokens
                .refresh_token
                .as_deref()
                .unwrap()
                .starts_with(REFRESH_TOKEN_PREFIX)
        );
        assert_eq!(tokens.expires_in, 900);
        assert_eq!(store.authenticate(&tokens.access_token), Some(account()));
        assert_eq!(
            store.redeem_code(&code, REDIRECT, VERIFIER).unwrap_err(),
            GrantError::Invalid
        );
    }

    #[test]
    fn authorization_code_requires_matching_verifier_and_redirect_uri() {
        let store = store();
        let wrong_verifier = "x".repeat(43);
        let code = store.issue_code(&request(), account()).unwrap();
        assert_eq!(
            store
                .redeem_code(&code, REDIRECT, &wrong_verifier)
                .unwrap_err(),
            GrantError::Invalid
        );
        // A failed attempt burns the code.
        assert_eq!(
            store.redeem_code(&code, REDIRECT, VERIFIER).unwrap_err(),
            GrantError::Invalid
        );

        let code = store.issue_code(&request(), account()).unwrap();
        assert_eq!(
            store
                .redeem_code(&code, "http://127.0.0.1:1/callback", VERIFIER)
                .unwrap_err(),
            GrantError::Invalid
        );
    }

    #[test]
    fn refresh_rotates_and_keeps_the_previous_access_token() {
        let store = store();
        let first = login(&store);
        let (second, who) = store
            .refresh(first.refresh_token.as_deref().unwrap())
            .unwrap();
        assert_eq!(who, account());
        assert_ne!(first.access_token, second.access_token);
        assert_ne!(first.refresh_token, second.refresh_token);
        assert_eq!(store.authenticate(&first.access_token), Some(account()));
        assert_eq!(store.authenticate(&second.access_token), Some(account()));
        store
            .refresh(second.refresh_token.as_deref().unwrap())
            .unwrap();
    }

    #[test]
    fn refresh_token_reuse_revokes_the_whole_login() {
        let store = store();
        let first = login(&store);
        let stolen = first.refresh_token.as_deref().unwrap();
        let (second, _) = store.refresh(stolen).unwrap();

        assert_eq!(
            store.refresh(stolen).unwrap_err(),
            GrantError::RefreshTokenReused(account())
        );
        assert_eq!(store.authenticate(&first.access_token), None);
        assert_eq!(store.authenticate(&second.access_token), None);
        assert_eq!(
            store
                .refresh(second.refresh_token.as_deref().unwrap())
                .unwrap_err(),
            GrantError::Invalid
        );
    }

    #[test]
    fn reuse_detection_does_not_touch_other_logins() {
        let store = store();
        let mine = login(&store);
        let theirs = login(&store);
        let token = mine.refresh_token.as_deref().unwrap();
        store.refresh(token).unwrap();
        assert!(store.refresh(token).is_err());
        assert_eq!(store.authenticate(&theirs.access_token), Some(account()));
    }

    #[test]
    fn access_tokens_are_not_refresh_tokens_and_vice_versa() {
        let store = store();
        let tokens = login(&store);
        assert_eq!(
            store.refresh(&tokens.access_token).unwrap_err(),
            GrantError::Invalid
        );
        assert_eq!(
            store.authenticate(tokens.refresh_token.as_deref().unwrap()),
            None
        );
    }

    #[test]
    fn revoking_either_token_ends_the_login() {
        let store = store();
        let tokens = login(&store);
        assert_eq!(store.revoke(&tokens.access_token), Some(account()));
        assert_eq!(store.authenticate(&tokens.access_token), None);
        assert!(
            store
                .refresh(tokens.refresh_token.as_deref().unwrap())
                .is_err()
        );

        let tokens = login(&store);
        assert_eq!(
            store.revoke(tokens.refresh_token.as_deref().unwrap()),
            Some(account())
        );
        assert_eq!(store.authenticate(&tokens.access_token), None);
        assert_eq!(store.revoke("mts_unknown"), None);
    }

    #[test]
    fn refreshing_never_extends_the_login_deadline() {
        let store = OAuthStore::new(Duration::from_secs(900), Some(Duration::from_secs(1000)));
        let tokens = login(&store);
        {
            let mut inner = store.lock();
            let grant = inner.grants.values_mut().next().unwrap();
            grant.deadline = Instant::now() + Duration::from_secs(100);
        }
        let (refreshed, _) = store
            .refresh(tokens.refresh_token.as_deref().unwrap())
            .unwrap();
        assert!(refreshed.expires_in <= 100, "{}", refreshed.expires_in);

        {
            let mut inner = store.lock();
            let grant = inner.grants.values_mut().next().unwrap();
            grant.deadline = Instant::now();
        }
        assert_eq!(
            store
                .refresh(refreshed.refresh_token.as_deref().unwrap())
                .unwrap_err(),
            GrantError::Invalid
        );
        assert_eq!(store.authenticate(&refreshed.access_token), None);
    }

    #[test]
    fn refresh_tokens_can_be_disabled() {
        let store = OAuthStore::new(Duration::from_secs(900), None);
        let tokens = login(&store);
        assert!(tokens.refresh_token.is_none());
        assert_eq!(store.authenticate(&tokens.access_token), Some(account()));
        assert_eq!(
            store.refresh("mtr_anything").unwrap_err(),
            GrantError::Invalid
        );
    }

    #[test]
    fn tokens_are_stored_hashed() {
        let store = store();
        let tokens = login(&store);
        let inner = store.lock();
        assert!(
            !inner
                .access
                .keys()
                .any(|key| key.as_slice() == tokens.access_token.as_bytes())
        );
        assert_eq!(tokens.access_token.len(), 4 + 43);
    }
}
