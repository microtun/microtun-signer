# microtun-firmware-signer

A small Rust service for signing MCUboot SHA-256 firmware digests with encrypted Ed25519 keys.

## Build and run

Requires Rust 1.98+.

```bash
cargo build --release --locked
cp config.example.toml config.toml
```

Configure the GitHub identities and policies, GitHub OAuth application, GitHub Actions OIDC verifier, server settings, and encrypted signing key in `config.toml`. Running the binary without a subcommand starts the service; the default config path is `/etc/microtun-firmware-signer/config.toml`, and `--config`/`MICROTUN_SIGNER_CONFIG` overrides it.

The public listener speaks plain HTTP. By default the signer refuses a non-loopback `Server.Listen`; terminate TLS at a trusted reverse proxy/load balancer, or explicitly set `Server.AllowNonLoopbackListen = true` only when the network path is otherwise protected.

Signing keys must be encrypted PKCS#8 using PBES2 with AES-256-CBC and either scrypt (`r >= 8` and `N*p >= 2^17`) or PBKDF2-HMAC-SHA-256/512 with at least 600,000 iterations. For example:

```bash
openssl pkcs8 -topk8 -v2 aes-256-cbc -scrypt \
  -scrypt_N 16384 -scrypt_r 8 -scrypt_p 8 \
  -in plain-key.pem -out firmware-signing-key.encrypted.pem
```

The OAuth client secret is read only from the systemd credential named by `GitHub.OAuthClientSecretCredential`, i.e. `$CREDENTIALS_DIRECTORY/<name>`. For local development, let systemd supply the credential:

```bash
systemd-run --user --pty --same-dir \
  -p LoadCredential=github-oauth-client-secret:/path/to/secret \
  ./target/release/microtun-firmware-signer --config ./config.toml
```

or point `CREDENTIALS_DIRECTORY` at a private directory by hand:

```bash
install -d -m 0700 ./dev-credentials
install -m 0600 /path/to/secret ./dev-credentials/github-oauth-client-secret
CREDENTIALS_DIRECTORY="$PWD/dev-credentials" \
  ./target/release/microtun-firmware-signer --config ./config.toml
```

All keys start locked on service startup, and only keys with `State = "active"` can be unlocked. Unlock active keys interactively after each service start:

```bash
./target/release/microtun-firmware-signer --config ./config.toml \
  unlock --key-id microtun-firmware-prod

# Equivalent short options:
./target/release/microtun-firmware-signer -c ./config.toml \
  unlock -k microtun-firmware-prod
```

The unlock passphrase is read from the terminal with hidden input; it is not accepted as a command-line argument, environment variable, or systemd credential. Service/admin CLI short options are `-c` for `--config`, `-k` for `--key-id`, and `-s` for `--socket`. The signing client uses `-k` for `--key-id`, `-u` for `--url`, and `-d` for `--digest`. `MICROTUN_SIGNER_ADMIN_SOCKET` may be used instead of `--socket`. The `unlock` subcommand uses the default admin socket path and only reads the service config when `--config` (or `MICROTUN_SIGNER_CONFIG`) is given explicitly.

The separate `microtun-firmware-sign` binary is the minimal client for the public signing API. Human GitHub users authenticate explicitly with `--github-device`; the command starts GitHub's OAuth device flow, prints the verification URL/code to stderr, exchanges the resulting GitHub token for a short-lived signer-local session, and then performs the signing request:

```bash
./target/release/microtun-firmware-sign \
  --github-device \
  --url https://signer.example.com/ \
  --key-id microtun-firmware-prod \
  --digest "$DIGEST_BASE64"
```

Enable **Device Flow** in the GitHub OAuth App settings. `--github-device` takes precedence over `MICROTUN_SIGNER_TOKEN`/`--token`. Without either an explicit bearer credential or `--github-device`, the client fails instead of unexpectedly becoming interactive. The CLI never receives the OAuth client secret. The signer verifies that the temporary GitHub token was issued to its configured OAuth App, requires a configured account with 2FA, revokes the GitHub token, and only then returns a short-lived signer-local session. RFC 8628 device authorization and the polling loop are handled by the `oauth2` crate, with the CLI preserving GitHub's required wait before the first token poll and normalizing GitHub's HTTP-200 OAuth error responses for the crate; GitHub-specific token verification, identity policy, replay protection, and revocation remain signer-side.

Automation can continue to pass an existing bearer credential through `MICROTUN_SIGNER_TOKEN` to avoid putting it in process arguments:

```bash
MICROTUN_SIGNER_TOKEN="$TOKEN" \
  ./target/release/microtun-firmware-sign \
  --url https://signer.example.com/ \
  --key-id microtun-firmware-prod \
  --digest "$DIGEST_BASE64"
```

`MICROTUN_SIGNER_URL` may be used instead of `--url`. The bearer credential can be a signer-local human session or a GitHub Actions OIDC JWT that satisfies the configured identity constraints. On success, `microtun-firmware-sign` writes only the base64 Ed25519 signature to stdout; device-flow instructions are written to stderr, so stdout remains suitable for scripts.

On Debian/systemd deployments, use the packaged systemd credential for the GitHub OAuth client secret; the example unit and `debian/README.Debian` document the expected layout and operator-group setup.

## HTTP API

The public API has five paths:

```text
GET  /healthz
GET  /v1/auth/github/device
POST /v1/auth/github/device
GET  /v1/public-key/{key_id}
POST /v1/sign/{key_id}
```

`GET /healthz` returns `204 No Content` when the process is serving requests.

Human users authenticate through the CLI device flow. `GET /v1/auth/github/device` returns only the public OAuth client ID, device-code URL, access-token URL, and requested scope. After GitHub authorizes the CLI, `POST /v1/auth/github/device` accepts the temporary GitHub access token, verifies with the OAuth client secret that the token belongs to this exact OAuth App, rejects replay, resolves the configured account, requires 2FA, and revokes the GitHub token before minting a signer-local session.

The exchange endpoint is limited to 10 attempts per 60 seconds per TCP peer and at most 8 concurrent exchanges. It deliberately uses the direct TCP peer address rather than trusting forwarding headers; behind a reverse proxy, clients therefore share the proxy's per-peer quota unless the deployment terminates the public listener differently. GitHub token revocation is fail-closed: if revocation cannot be confirmed, no signer-local session is issued. A successful exchange returns only the signer-local bearer credential and its lifetime:

```json
{
  "access_token": "<signer-local-token>",
  "expires_in": 900
}
```

`GET /v1/public-key/{key_id}` returns only the Ed25519 public key as an SPKI PEM (`application/x-pem-file`). The key must have been unlocked since service startup; no key metadata is exposed.

`POST /v1/sign/{key_id}` requires `Authorization: Bearer <token>` and `Content-Type: application/json`. The body contains exactly one 32-byte MCUboot SHA-256 digest encoded as base64:

```json
{
  "digest": "<32-byte-digest-as-base64>"
}
```

A successful response contains only the Ed25519 signature:

```json
{
  "signature": "<base64-ed25519-signature>"
}
```

Errors use the HTTP status plus a compact body for programmatic handling and audit correlation:

```json
{
  "error": "<stable-error-code>",
  "request_id": "01..."
}
```

For GitHub Actions callers, the bearer token is a GitHub Actions OIDC JWT. Repository, commit, ref, protected-ref status, actor, workflow, environment, event, run ID, and run attempt come from the verified token and are recorded in the audit log. Tokens must resolve unambiguously to a configured `github-actions` identity and are single-use within the signer process via their OIDC `jti`.

Signing from GitHub Actions requires an authenticated tag ref that GitHub reports as protected by a ruleset. Any `github-actions` identity granted the `sign` action must also configure `WorkflowPath`, `AllowedEventNames`, and `RequiredEnvironment`; the example configuration shows the intended protected-environment setup. Human OAuth sessions use the same signing request body but do not have release-provenance requirements.

Key unlock is an admin operation only, available over the Unix-domain socket configured by `Server.AdminSocketPath`/`Server.AdminSocketMode`/`Server.AdminSocketGroup` at `POST /v1/unlock/{key_id}`. It returns `204 No Content` on success. Restarting the service relocks every key and invalidates all signer-local human OAuth sessions because both are held only in process memory.

## Development

```bash
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
```

Debian packages can be built with `Dockerfile.debian`; tagged releases publish amd64 and arm64 `.deb` artifacts.

Release tags must use canonical `vX.Y.Z` SemVer syntax, must exactly match both `[package].version` in `Cargo.toml` and the top version in `debian/changelog`, and must point to a commit contained in `main`; CI checks these conditions before release artifacts are published.
