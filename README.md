# microtun-firmware-signer

A small Rust service for signing MCUboot SHA-256 firmware digests with encrypted Ed25519 keys.

The signer keeps key custody separate from CI: callers authenticate with GitHub, authorization is defined explicitly in TOML, and signing keys are only decrypted in memory after a local operator unlocks them.

## Security model

- Signing keys are encrypted PKCS#8 PEM files and always start **locked** after service startup. Key files must use PBES2 with AES-256 and either scrypt (r ≥ 8, N·p ≥ 2^17) or PBKDF2-HMAC-SHA-256/512 with at least 600,000 iterations; weaker files are refused at startup.
- Key and secret files are opened without following symlinks and validated on the open file descriptor: regular file, owned by root or the service user, no group write and no access for other users.
- Key passphrases are entered interactively through `microtun-firmware-signer unlock` and sent only over a local Unix-domain socket. Decryption runs on the blocking thread pool, one key at a time, so an expensive KDF never stalls request handling. The socket belongs to a dedicated operators group (`Server.AdminSocketGroup`) that cannot read the key file or service configuration.
- Human users authenticate through the signer's GitHub OAuth flow; GitHub Actions authenticates with GitHub OIDC. Raw GitHub OAuth tokens are not accepted by the signing API.
- `[[Policy]]` entries bind named identities to allowed actions and key IDs.
- GitHub Actions signing requires a tag protected by a GitHub ruleset (the `ref_protected` claim) and a job running in the identity's `RequiredEnvironment`. Configure that environment's deployment rules to allow only protected tags. Repository, commit, ref, workflow, event, run ID, and run attempt come directly from the verified OIDC token; clients do not echo that provenance in the request body.
- Each GitHub Actions OIDC token can be used for one request (`jti` replay protection). Mint a fresh token per signing request.
- JWKS refreshes are single-flight and triggered by an unknown `kid` at most once a minute; previously fetched keys stay usable for up to 24 hours if GitHub is unreachable.
- Human OAuth uses PKCE and a browser-bound, HMAC-authenticated `__Host-` state cookie; no login state is stored server-side. The signer requests `read:user`, refuses accounts without GitHub two-factor authentication, and revokes the GitHub token immediately after resolving the account.
- Human sessions are short-lived (15 minutes by default, 1 hour maximum) and are stored only as SHA-256 hashes in process memory, so restarting the signer invalidates all active human sessions. Human OAuth sessions are trusted signers: signing requests contain no caller-supplied release or GitHub provenance metadata.
- The TCP listener must be a loopback address unless `Server.AllowNonLoopbackListen = true`. Terminate TLS at a trusted reverse proxy. Never expose or proxy the admin socket.

## Build and run

Requires Rust 1.85+.

```bash
cargo build --release --locked
cp config.example.toml config.toml
```

Configure the GitHub identities, policies, OAuth application, and encrypted signing key in `config.toml`.

Encrypt the signing key with a strong KDF, for example:

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

Active keys must be unlocked after every service start:

```bash
./target/release/microtun-firmware-signer --config ./config.toml \
  unlock --key-id microtun-firmware-prod

# Equivalent short options:
./target/release/microtun-firmware-signer -c ./config.toml \
  unlock -k microtun-firmware-prod
```

CLI short options are `-c` for `--config`, `-k` for `--key-id`, `-s` for `--socket`, `-u` for `--url`, and `-d` for `--digest`. The `unlock` subcommand uses the default admin socket path and only reads the config when `--config` (or `MICROTUN_SIGNER_CONFIG`) is given explicitly.

The binary can also act as a client for the public signing API. Pass the bearer credential through `MICROTUN_SIGNER_TOKEN` to avoid putting it in the process arguments:

```bash
MICROTUN_SIGNER_TOKEN="$TOKEN" \
  ./target/release/microtun-firmware-signer sign \
  --url https://signer.example.com/ \
  --key-id microtun-firmware-prod \
  --digest "$DIGEST_BASE64"
```

`MICROTUN_SIGNER_URL` may be used instead of `--url`. On success, `sign` writes only the base64 Ed25519 signature to stdout, which makes it suitable for scripts.

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

Human users start authentication at `GET /v1/auth/github` in a browser; the callback must complete in the same browser. The callback returns only the signer-local bearer credential and its lifetime:

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

For GitHub Actions callers, repository, commit, ref, actor, workflow, event, run ID, and run attempt come directly from the verified OIDC token and are recorded in the audit log. Actions signing still requires an authenticated tag ref. Human OAuth sessions use the same signing request body and do not supply release provenance.

Key unlock is an admin operation only, available over the Unix-domain socket configured by `Server.AdminSocketPath`/`Server.AdminSocketMode`/`Server.AdminSocketGroup` at `POST /v1/unlock/{key_id}`. It returns `204 No Content` on success. Restarting the service invalidates all signer-local human OAuth sessions because those sessions exist only in process memory.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
```

Debian packages can be built with `Dockerfile.debian`; CI publishes amd64 and arm64 `.deb` artifacts for tagged releases.

Release tags must use canonical `vX.Y.Z` SemVer syntax and must exactly match the `[package].version` in `Cargo.toml`; CI checks this before release artifacts are built or published.
