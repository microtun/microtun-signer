# microtun-firmware-signer

Rust service for signing Microtun firmware digests with configured Ed25519
a signing key and GitHub-backed identities.

## Build Debian Package

### Package for Local Architecture


```sh
docker buildx build -f Dockerfile.debian --target debs --output type=local,dest=. .
```

### Package for ARM64

```sh
docker buildx build -f Dockerfile.debian --platform linux/arm64 --target debs --output type=local,dest=. .
```
## Public key access

`GET /v1/keys/{key_id}` is public and does not require a GitHub OAuth session,
a bearer token, or a policy grant. Authorization policies apply only to signing.

