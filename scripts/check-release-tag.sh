#!/usr/bin/env bash
set -euo pipefail

if (( $# > 1 )); then
    echo "usage: $0 [tag]" >&2
    exit 2
fi

tag="${1:-${GITHUB_REF_NAME:-}}"
if [[ -z "$tag" ]]; then
    echo "error: release tag is required (argument or GITHUB_REF_NAME)" >&2
    exit 2
fi

# Release tags are deliberately limited to canonical SemVer release versions:
# vMAJOR.MINOR.PATCH, with no leading zeroes, pre-release, or build metadata.
semver_tag_re='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
if [[ ! "$tag" =~ $semver_tag_re ]]; then
    echo "error: release tag '$tag' must use canonical vX.Y.Z SemVer format" >&2
    exit 1
fi

cargo_version="$({
    awk '
        /^\[package\][[:space:]]*$/ { in_package = 1; next }
        /^\[/ && in_package { exit }
        in_package && /^[[:space:]]*version[[:space:]]*=/ {
            line = $0
            sub(/^[^=]*=[[:space:]]*/, "", line)
            sub(/[[:space:]]*#.*/, "", line)
            gsub(/^[[:space:]]*"|"[[:space:]]*$/, "", line)
            print line
            exit
        }
    ' Cargo.toml
} || true)"

if [[ -z "$cargo_version" ]]; then
    echo "error: could not read [package].version from Cargo.toml" >&2
    exit 1
fi

debian_version="$(sed -nE '1s/^[^[:space:]]+[[:space:]]+\(([^)]+)\)[[:space:]]+.*/\1/p' debian/changelog)"
if [[ -z "$debian_version" ]]; then
    echo "error: could not read package version from debian/changelog" >&2
    exit 1
fi

expected_tag="v${cargo_version}"
if [[ "$tag" != "$expected_tag" ]]; then
    echo "error: release tag '$tag' does not match Cargo.toml version '$cargo_version' (expected '$expected_tag')" >&2
    exit 1
fi

expected_debian_tag="v${debian_version}"
if [[ "$tag" != "$expected_debian_tag" ]]; then
    echo "error: release tag '$tag' does not match debian/changelog version '$debian_version' (expected '$expected_debian_tag')" >&2
    exit 1
fi

echo "release tag '$tag' matches Cargo.toml and debian/changelog version '$cargo_version'"
