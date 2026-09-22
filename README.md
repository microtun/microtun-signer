# microtun-signer

A small Rust service that signs MCUboot SHA-256 firmware digests with Ed25519 keys.

It supports:

- GitHub users via OAuth device flow
- GitHub Actions via OIDC
- Signing keys are encrypted at rest and must be unlocked after every restart

## Build

Requires Rust 1.98+.

```bash
cargo build --release --locked
cp config.example.toml config.toml
```

Edit `config.toml` with your server, GitHub, access-policy, and signing-key settings.

## Signing key

The private key must be encrypted PKCS#8.

Example:

```bash
openssl pkcs8 -topk8 -v2 aes-256-cbc -scrypt \
  -scrypt_N 16384 -scrypt_r 8 -scrypt_p 8 \
  -in plain-key.pem -out firmware-signing-key.encrypted.pem
```

## Run the service

```bash
./target/release/microtun-signer
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
./target/release/microtun-signer-client \
  --url https://signer.example.com/ \
  sign \
  --github-device \
  --key-id microtun-firmware-prod \
  --digest "$DIGEST_BASE64"
```

Enable **Device Flow** in the GitHub OAuth App.

### Existing bearer token / GitHub Actions

```bash
MICROTUN_SIGNER_TOKEN="$TOKEN" \
  ./target/release/microtun-signer-client \
  --url https://signer.example.com/ \
  sign \
  --key-id microtun-firmware-prod \
  --digest "$DIGEST_BASE64"
```

`MICROTUN_SIGNER_URL` can be used instead of `--url`.

On success, the client writes only the base64 Ed25519 signature to stdout.

## Get a public key

```bash
./target/release/microtun-signer-client \
  --url https://signer.example.com/ \
  public-key \
  --key-id microtun-firmware-prod
```

On success, the client writes the PEM-encoded Ed25519 public key to stdout. The signing key must be unlocked before its public key is available.

## API

```text
GET  /healthz
GET  /v1/auth/github/device
POST /v1/auth/github/device
GET  /v1/public-key/{key_id}
POST /v1/sign/{key_id}
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
  "signature": "<base64-ed25519-signature>"
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

This project is proprietary source-available software.

The source is published for transparency, review, and evaluation. It is not
open-source software.

Commercial or production use requires a separate written license.

See [LICENSE](LICENSE) for details.
