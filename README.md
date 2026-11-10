# microtun-signer

A small Rust service that signs firmware digests.

It supports:

- GitHub users via the OAuth authorization code flow (browser sign-in, PKCE, refresh tokens)
- GitHub Actions via OIDC
- Signing keys are encrypted at rest and must be unlocked after every restart

## Supported algorithms

- P-256 (secp256r1 / prime256v1)
- secp256k1 (RPI Pico 2)
- RSA-PSS (Espressif ESP32 SBV2)

## Build

Requires Rust 1.98+.

```bash
cargo build --release --locked
cp config.example.toml config.toml
```

Edit `config.toml` with your server, GitHub, access-policy, and signing-key settings.

## Signing key

The private key must be encrypted PKCS#8. Every `[[Key]]` must explicitly set
`Algorithm = "p256"` (also accepts `"secp256r1"`),
`Algorithm = "secp256k1"`, or `Algorithm = "rsa-pss"`.

P-256 / secp256r1 example:

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 | \
  openssl pkcs8 -topk8 \
  -v2 aes-256-cbc \
  -scrypt -scrypt_N 16384 -scrypt_r 8 -scrypt_p 8 \
  -out firmware-signing-key.encrypted.pem
```

secp256k1 example:

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp256k1 | \
  openssl pkcs8 -topk8 \
    -v2 aes-256-cbc \
    -scrypt -scrypt_N 16384 -scrypt_r 8 -scrypt_p 8 \
    -out firmware-signing-key.encrypted.pem
```

RSA-PSS example:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 | \
  openssl pkcs8 -topk8 \
    -v2 aes-256-cbc \
    -scrypt -scrypt_N 16384 -scrypt_r 8 -scrypt_p 8 \
    -out firmware-signing-key.encrypted.pem
```

## Run the service

```bash
./target/release/microtun-signer serve
```

The GitHub OAuth client secret is read from a systemd credential via
`$CREDENTIALS_DIRECTORY/<credential-name>`; it is not stored in `config.toml`.

`[Server] PublicURL` must be the URL users reach the signer at, and the GitHub
OAuth App's **Authorization callback URL** must be set to
`<PublicURL>/v1/auth/github/callback`. Device Flow does not need to be enabled
on the OAuth App.

For local development, you can point `CREDENTIALS_DIRECTORY` at a private directory containing the secret.

The public listener is plain HTTP. Use a trusted TLS reverse proxy for non-loopback deployments.

## Unlock a key

Keys start locked after every service restart.

```bash
./target/release/microtun-signer unlock -k microtun-firmware-prod
```

The passphrase is entered interactively and is not accepted through command-line arguments or environment variables.

### Unlock several keys at once

Keys encrypted with the same passphrase can be grouped in a top-level
`[[Keyring]]`. The keyring explicitly owns its member list:

```toml
[[Keyring]]
ID = "firmware-prod"
Keys = ["microtun-p256-prod", "microtun-esp32-prod"]

[[Key]]
ID = "microtun-p256-prod"
Algorithm = "p256"
PEMPath = "/etc/microtun-signer/p256-prod.encrypted.pem"

[[Key]]
ID = "microtun-esp32-prod"
Algorithm = "rsa-pss"
PEMPath = "/etc/microtun-signer/esp32-prod.encrypted.pem"
```

Keyring IDs must be unique, `Keys` must contain at least one existing key ID,
and each key can belong to at most one keyring. Keys not listed in a keyring
can still be unlocked individually. The `Keyring` field on `[[Key]]` is no
longer supported.

```bash
./target/release/microtun-signer unlock --keyring firmware-prod
```

One passphrase prompt unlocks every active key in the keyring. The unlock is
all-or-nothing: if the passphrase doesn't open every locked, active member,
none of them are unlocked and the command names the keys that didn't match.
Keys that are already unlocked are left alone, and retired or disabled keys are
skipped. Results follow the order of the keyring's `Keys` list. Individual keys
in a keyring can still be unlocked with `--key-id`.

## Sign firmware

### GitHub user

```bash
./target/release/microtun-signer sign \
  --url https://signer.example.com/ \
  --github-login \
  --key-id microtun-firmware-prod \
  --digest "$DIGEST_BASE64"
```

The first run prints a sign-in URL and opens it in your browser (pass
`--no-browser` to only print it). After you sign in with GitHub, the browser is
redirected to a temporary listener the CLI opened on `127.0.0.1`, and the
command continues. The browser therefore has to run on the same machine as the
CLI.

How it works:

- The signer is a small OAuth 2.0 authorization server for the CLI. The CLI
  runs the authorization code flow with PKCE against it, using a loopback
  redirect URI ([RFC 8252](https://www.rfc-editor.org/rfc/rfc8252)).
- The signer sends the browser on to GitHub, exchanges GitHub's code itself
  with the client secret, checks that the account is a configured identity
  with two-factor authentication enabled, and revokes the GitHub token again.
  GitHub credentials never reach the CLI.
- The CLI receives a short-lived access token (`OAuthSessionTTLSeconds`,
  default 15 minutes) and a refresh token, and caches both (see below). Later
  runs reuse the access token, or silently trade the
  refresh token for a new pair, until `OAuthRefreshTTLSeconds` (default 8
  hours, `0` to disable refresh tokens) has passed since the GitHub sign-in.
  Then the browser is needed again.
- Refresh tokens are single-use and rotate on every refresh. Presenting an
  already-used refresh token revokes that whole login. Refreshing does not go
  back to GitHub, so a change to the account (for example 2FA being turned
  off) takes effect at the next browser sign-in.

The cached session is kept in the operating system's credential store:
Keychain on macOS, and the Secret Service (GNOME Keyring, KWallet, ...) on
Linux. Where there is none, typically on a headless machine, it falls back to
a file readable only by you under `$XDG_RUNTIME_DIR` (or the user cache
directory). Set `MICROTUN_SIGNER_SESSION_CACHE_DIR` to an absolute path to use
a file in that directory instead of the credential store.

End the session early, on the signer and locally, with:

```bash
./target/release/microtun-signer logout --url https://signer.example.com/
```

### GitHub Actions

Grant the signing job `id-token: write` permission, then call the CLI directly:

```yaml
jobs:
  sign:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@v4
      # Build the firmware and set DIGEST_BASE64 in an earlier step.
      - name: Sign firmware
        run: |
          microtun-signer sign \
            --url https://signer.example.com/ \
            --github-actions \
            --key-id microtun-firmware-prod \
            --digest "$DIGEST_BASE64"
```

Each `sign` invocation requests its own fresh OIDC JWT using GitHub's
`ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN` environment
variables, and sends it directly as the signing API bearer token. No token is
cached or printed. `--audience` defaults to `microtun-signer`, matching the
server's default `[GitHubActions] Audience`; if the server is configured with a
different audience, pass `--audience "your-configured-audience"` alongside
`--github-actions`.

When no other credential is selected, the CLI also automatically uses GitHub
Actions OIDC if `ACTIONS_ID_TOKEN_REQUEST_URL` is present, so the
`--github-actions` flag may be omitted in such a job. `--github-actions` takes
precedence over `MICROTUN_SIGNER_TOKEN`/`--token` when explicitly supplied;
`--github-login` is mutually exclusive with `--github-actions`. An explicitly
provided bearer token takes precedence over automatic OIDC detection.

### Existing bearer token

```bash
MICROTUN_SIGNER_TOKEN="$TOKEN" \
  ./target/release/microtun-signer sign \
  --url https://signer.example.com/ \
  --key-id microtun-firmware-prod \
  --digest "$DIGEST_BASE64"
```

On success, the command writes only the base64 signature to stdout. P-256
(secp256r1) and secp256k1 signatures are ECDSA over the supplied 32-byte SHA-256
digest (treated as a prehash, **not hashed again**) and use the fixed-width
64-byte `r || s` encoding (32-byte big-endian `r`, then 32-byte big-endian `s`;
**not** ASN.1 DER). RSA-PSS signatures are 256 bytes for RSA-2048 and 384
bytes for RSA-3072.

## Get a public key

```bash
./target/release/microtun-signer public-key \
  --url https://signer.example.com/ \
  --key-id microtun-firmware-prod
```

On success, the command writes the PEM-encoded SubjectPublicKeyInfo public key to stdout. The signing key must be unlocked before its public key is available.

## API

```text
GET  /healthz
GET  /version
GET  /v1/auth/authorize          OAuth 2.0 authorization endpoint (redirects to GitHub)
GET  /v1/auth/github/callback    GitHub redirects the browser back here
POST /v1/auth/token              OAuth 2.0 token endpoint (authorization_code, refresh_token)
POST /v1/auth/revoke             OAuth 2.0 token revocation
GET  /v1/public-key/{key_id}
POST /v1/sign/{key_id}
```

The version endpoint returns the running package version:

```json
{
  "version": "0.8.0"
}
```

Signing requests use:

```json
{
  "digest": "<32-byte-SHA-256-digest-as-base64>"
}
```

Successful responses use:

```json
{
  "signature": "<base64-signature>"
}
```

## Development

```bash
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
```

## Deployment notes

- Debian/systemd files are in `debian/` and `deploy/`.
- Restarting the service locks all keys again and invalidates all human sessions, including their refresh tokens.
- GitHub Actions signing policies are configured in `config.toml`; start from `config.example.toml`.
- Release tags must be `vX.Y.Z` and match both `Cargo.toml` and `debian/changelog`.

## License

Microtun is **dual-licensed**:

- **Noncommercial license:** [PolyForm Noncommercial License 1.0.0](LICENSE). 
  You may use, modify, and distribute
  Microtun for purposes permitted by that license, including its provisions
  for qualifying noncommercial organizations. This is a source-available
  license, **not an open-source license**.
- **Commercial license:** A separate written commercial license is
  **available upon request**. Commercial rights are granted only under a 
  separately agreed commercial license, not by the 
  PolyForm Noncommercial License or merely by making a request.