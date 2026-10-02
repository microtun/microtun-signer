# microtun-signer

A small Rust service that signs MCUboot firmware digests.

It supports:

- GitHub users via OAuth device flow
- GitHub Actions via OIDC
- Signing keys are encrypted at rest and must be unlocked after every restart

## Supported algorithms

- Ed25519 (recommended)
- secp256k1 (RPI Pico 2)
- RSA-PSS with SHA-256 (MCUboot RSA-2048/RSA-3072)

## Build

Requires Rust 1.98+.

```bash
cargo build --release --locked
cp config.example.toml config.toml
```

Edit `config.toml` with your server, GitHub, access-policy, and signing-key settings.

## Signing key

The private key must be encrypted PKCS#8. Every `[[Key]]` must explicitly set
`Algorithm = "ed25519"`, `Algorithm = "secp256k1"`, or `Algorithm = "rsa-pss"`.

Ed25519 example:

```bash
openssl genpkey -algorithm ED25519 | openssl pkcs8 -topk8 \
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

### Existing bearer token / GitHub Actions

```bash
MICROTUN_SIGNER_TOKEN="$TOKEN" \
  ./target/release/microtun-signer sign \
  --url https://signer.example.com/ \
  --key-id microtun-firmware-prod \
  --digest "$DIGEST_BASE64"
```

On success, the command writes only the base64 signature to stdout. Ed25519
signatures are 64 bytes. secp256k1 signatures are ECDSA over the supplied digest
and use the fixed-width 64-byte `r || s` encoding (32-byte big-endian `r`, then
32-byte big-endian `s`). RSA-PSS signatures are 256 bytes for RSA-2048 and 384
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