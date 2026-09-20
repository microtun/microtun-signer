# microtun-firmware-signer

A small Rust service for signing MCUboot SHA-256 firmware digests with encrypted Ed25519 keys.

The signer is designed to keep key custody separate from CI: callers authenticate with GitHub, authorization is defined explicitly in TOML, and signing keys are only decrypted in memory after a local operator unlocks them.

## Security model

- Signing keys are encrypted PKCS#8 PEM files and always start **locked** after service startup.
- Key passphrases are entered interactively through `microtun-firmware-signer unlock` and sent only over a local Unix-domain socket.
- Human users authenticate through the signer's GitHub OAuth flow; GitHub Actions authenticates with GitHub OIDC. Raw GitHub OAuth tokens are not accepted by the signing API.
- `[[Policy]]` entries bind named identities to allowed actions and key IDs.
- Signing is restricted to release-tag context; GitHub Actions requests must also match the authenticated repository, ref, commit, workflow, event, run ID, and run attempt.
- The TCP listener is intended for loopback/private networking. Terminate TLS at a trusted reverse proxy or load balancer. Never expose or proxy the unlock socket.

## Build and run

Requires Rust 1.85+.

```bash
cargo build --release --locked
cp config.example.toml config.toml
```

Configure the GitHub identities, policies, OAuth application, and encrypted signing key in `config.toml`. For local development, provide the OAuth client secret directly or via a file:

```bash
export MICROTUN_SIGNER_GITHUB_OAUTH_CLIENT_SECRET='...'
# or: MICROTUN_SIGNER_GITHUB_OAUTH_CLIENT_SECRET_FILE=/path/to/secret

./target/release/microtun-firmware-signer --config ./config.toml
```

Active keys must be unlocked after every service start:

```bash
./target/release/microtun-firmware-signer --config ./config.toml \
  unlock --key microtun-firmware-prod
```

On Debian/systemd deployments, use the packaged systemd credential for the GitHub OAuth client secret; the example unit and `debian/README.Debian` document the expected layout.

## HTTP API

The service is intended to run on its own domain and serves the public API directly from the domain root:

```text
GET  /healthz
GET  /v1/auth/github/login
GET  /v1/auth/github/callback
GET  /v1/keys/{key_id}
POST /v1/signatures
```

`POST /v1/signatures` requires `Authorization: Bearer <token>` and `Content-Type: application/json`. The message is exactly one 32-byte MCUboot SHA-256 digest encoded as base64; the response contains a base64 Ed25519 signature.

Example request shape:

```json
{
  "api_version": "microtun-signing/v1",
  "key": {
    "id": "microtun-firmware-prod",
    "fingerprint": "sha256:<public-key-fingerprint>"
  },
  "signature_algorithm": "ed25519",
  "message": {
    "type": "mcuboot-sha256",
    "encoding": "base64",
    "value": "<32-byte-digest-as-base64>"
  },
  "context": {
    "board": "<board>",
    "version": "1.2.3",
    "repository": "owner/repo",
    "repository_id": "123456789",
    "ref": "refs/tags/v1.2.3",
    "ref_type": "tag",
    "commit_sha": "<git-sha>"
  }
}
```

GitHub Actions callers must additionally provide `event_name`, `workflow_ref`, `run_id`, and `run_attempt` matching the OIDC token claims.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
```

Debian packages can be built with `Dockerfile.debian`; CI publishes amd64 and arm64 `.deb` artifacts for tagged releases.

Release tags must use canonical `vX.Y.Z` SemVer syntax and must exactly match the `[package].version` in `Cargo.toml`; CI checks this before release artifacts are built or published.