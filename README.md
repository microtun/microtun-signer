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
- The TCP listener is intended for loopback/private networking. Terminate TLS at a trusted reverse proxy or load balancer. Never expose or proxy the unlock socket.

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
```

On Debian/systemd deployments, use the packaged systemd credential for the GitHub OAuth client secret; the example unit and `debian/README.Debian` document the expected layout.

## HTTP API

The service is intended to run on its own domain and serves the public API directly from the domain root:

```text
GET  /healthz
GET  /v1/auth/github/login
GET  /v1/auth/github/callback
GET  /v1/keys/{key_id}
POST /v1/keys/{key_id}/signatures
```

`POST /v1/keys/{key_id}/signatures` requires `Authorization: Bearer <token>` and `Content-Type: application/json`. `digest` is exactly one 32-byte MCUboot SHA-256 digest encoded as base64. The returned `signature` is a base64 Ed25519 signature.

### GitHub Actions

Actions callers send only the digest:

```json
{
  "digest": "<32-byte-digest-as-base64>"
}
```

The signer still requires an authenticated GitHub tag ref for Actions callers. Tag names are treated as opaque provenance; no release metadata is derived from them or accepted in the request body.

Repository, repository ID, commit SHA, ref, actor, workflow, event, run ID, and run attempt are taken directly from the verified OIDC claims and recorded in the audit log.

### Human OAuth session

Human callers use the same minimal request body:

```json
{
  "digest": "<32-byte-digest-as-base64>"
}
```

The signing body accepts no additional metadata: repository, ref, commit, workflow, algorithm, message type, encoding, and key ID are all server-side or fixed by the endpoint contract.

A successful signing response is intentionally small:

```json
{
  "request_id": "01...",
  "key": {
    "id": "microtun-firmware-prod"
  },
  "signature": "<base64-ed25519-signature>"
}
```

`GET /v1/keys/{key_id}` returns the key ID, lifecycle state, lock state, and the public key PEM when the key is unlocked.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
```

Debian packages can be built with `Dockerfile.debian`; CI publishes amd64 and arm64 `.deb` artifacts for tagged releases.

Release tags must use canonical `vX.Y.Z` SemVer syntax and must exactly match the `[package].version` in `Cargo.toml`; CI checks this before release artifacts are built or published.
