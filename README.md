# microtun-firmware-signer

A small Rust service for signing MCUboot SHA-256 firmware digests with encrypted Ed25519 keys.

The signer keeps key custody separate from CI: callers authenticate with GitHub, authorization is defined explicitly in TOML, and signing keys are only decrypted in memory after a local operator unlocks them.

## Security model

- Signing keys are encrypted PKCS#8 PEM files and always start **locked** after service startup.
- Key passphrases are entered interactively through `microtun-firmware-signer unlock` and sent only over a local Unix-domain socket.
- Human users authenticate through the signer's GitHub OAuth flow; GitHub Actions authenticates with GitHub OIDC. Raw GitHub OAuth tokens are not accepted by the signing API.
- `[[Policy]]` entries bind named identities to allowed actions and key IDs.
- GitHub Actions signing is restricted to authenticated release-tag refs. Repository, commit, ref, workflow, event, run ID, and run attempt come directly from the verified OIDC token; clients do not echo that provenance in the request body.
- Human OAuth sessions are trusted signers. Signing requests contain no caller-supplied release or GitHub provenance metadata.
- The TCP listener is intended for loopback/private networking. Terminate TLS at a trusted reverse proxy or load balancer. Never expose or proxy the admin socket.

## Build and run

Requires Rust 1.85+.

```bash
cargo build --release --locked
cp config.example.toml config.toml
```

Configure the GitHub identities, policies, OAuth application, and encrypted signing key in `config.toml`.

For local development, provide the OAuth client secret directly or via a file:

```bash
export MICROTUN_SIGNER_GITHUB_OAUTH_CLIENT_SECRET='...'
# or: MICROTUN_SIGNER_GITHUB_OAUTH_CLIENT_SECRET_FILE=/path/to/secret

./target/release/microtun-firmware-signer --config ./config.toml
```

Active keys must be unlocked after every service start:

```bash
./target/release/microtun-firmware-signer --config ./config.toml \
  unlock --key microtun-firmware-prod

# Equivalent short options:
./target/release/microtun-firmware-signer -c ./config.toml \
  unlock -k microtun-firmware-prod
```

CLI short options are `-c` for `--config`, `-k` for `--key`, and `-s` for `--socket`.

On Debian/systemd deployments, use the packaged systemd credential for the GitHub OAuth client secret; the example unit and `debian/README.Debian` document the expected layout.

## HTTP API

The public API has five endpoints:

```text
GET  /healthz
GET  /v1/auth/github
GET  /v1/auth/github/callback
GET  /v1/public-key/{key_id}
POST /v1/sign/{key_id}
```

`GET /healthz` returns `204 No Content` when the process is serving requests.

Human users start authentication at `GET /v1/auth/github`. The callback returns only the signer-local bearer credential and its lifetime:

```json
{
  "access_token": "<signer-local-token>",
  "expires_in": 28800
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

For GitHub Actions callers, repository, commit, ref, actor, workflow, event, run ID, and run attempt come directly from the verified OIDC token and are recorded in the audit log. Actions signing still requires an authenticated tag ref. Human OAuth sessions use the same signing request body and do not supply release provenance.

Key unlock is a local management operation only, available over the Unix-domain socket configured by `Server.AdminSocketPath`/`Server.AdminSocketMode` at `POST /v1/unlock/{key_id}`; successful unlocks return `204 No Content`.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
```

Debian packages can be built with `Dockerfile.debian`; CI publishes amd64 and arm64 `.deb` artifacts for tagged releases.

Release tags must use canonical `vX.Y.Z` SemVer syntax and must exactly match the `[package].version` in `Cargo.toml`; CI checks this before release artifacts are built or published.
