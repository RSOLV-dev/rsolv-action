#!/usr/bin/env bash
# Checks that a sandbox image archive (buildx's docker exporter with OCI media types, which is
# also an OCI layout) holds exactly one linux/<arch> image manifest whose bytes hash to the digest
# it's listed under, and prints that digest. With an expected digest, it must also match.
#   verify-sandbox-oci.sh <archive.tar> <amd64|arm64> [sha256:<hex>]
set -euo pipefail
archive=${1:-} arch=${2:-} want=${3:-}
[[ -f $archive && $arch =~ ^(amd64|arm64)$ && ( -z $want || $want =~ ^sha256:[0-9a-f]{64}$ ) ]] ||
  { echo "usage: verify-sandbox-oci.sh <archive.tar> <amd64|arm64> [sha256:<hex>]" >&2; exit 2; }
fail() { echo "::error::$archive: $*" >&2; exit 1; }
index=$(tar -xOf "$archive" index.json) || fail "no index.json"
jq -e --arg a "$arch" '.manifests | length == 1 and (.[0] |
  .mediaType == "application/vnd.oci.image.manifest.v1+json" and .platform.os == "linux" and .platform.architecture == $a)' \
  <<<"$index" >/dev/null || fail "expected exactly one linux/$arch OCI image manifest"
digest=$(jq -r '.manifests[0].digest' <<<"$index")
[[ $digest =~ ^sha256:[0-9a-f]{64}$ ]] || fail "malformed digest $digest"
hex=${digest#sha256:}
[ "$(tar -xOf "$archive" "blobs/sha256/$hex" | sha256sum | cut -d' ' -f1)" = "$hex" ] || fail "manifest blob doesn't hash to $digest"
[ -z "$want" ] || [ "$digest" = "$want" ] || fail "holds $digest, expected $want"
echo "$digest"
