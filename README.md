# microtun-signer

A small Rust service that signs MCUboot firmware digests.

It supports:

- GitHub users via OAuth device flow
- GitHub Actions via OIDC
- Signing keys are encrypted at rest and must be unlocked after every restart

## Supported algorithms

- P-256 (secp256r1 / prime256v1)
- secp256k1 (RPI Pico 2)
- RSA-PSS (Espressif ESP32)

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

For local development, you can point `CREDENTIALS_DIRECTORY` at a private directory containing the secret.

The public listener is plain HTTP. Use a trusted TLS reverse proxy for non-loopback deployments.

## Unlock a key

Keys start locked after every service restart.

```bash
./target/release/microtun-signer unlock -k microtun-firmware-prod
```

The passphrase is entered interactively and is not accepted through command-line arguments or environment variables.

## Sign firmware

### GitHub user

```bash
./target/release/microtun-signer sign \
  --url https://signer.example.com/ \
  --github-login \
  --key-id microtun-firmware-prod \
  --digest "$DIGEST_BASE64"
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
GET  /v1/auth/github/device
POST /v1/auth/github/device
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
- Restarting the service locks all keys again and invalidates local human sessions.
- GitHub Actions signing policies are configured in `config.toml`; start from `config.example.toml`.
- Release tags must be `vX.Y.Z` and match both `Cargo.toml` and `debian/changelog`.

## License

Microtun is **source-available software**, not open-source software.

The source code is made available for transparency, inspection, security research, auditing, and evaluation. You may:

- View and inspect the source code.
- Make reasonable copies for testing, auditing, evaluation, or security research.
- Compile, run, and modify the software as reasonably necessary for evaluation.
- Evaluate the software for up to **60 days** from the first time you compile or run it for a particular evaluation.

The license does **not** permit production, operational, or commercial use. You may not use Microtun to provide products or services, incorporate it into another product or service, commercially exploit it, or distribute modified versions except where expressly permitted by the license.

See [`LICENSE`](LICENSE) for the complete terms.