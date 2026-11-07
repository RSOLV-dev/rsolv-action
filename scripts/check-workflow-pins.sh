#!/usr/bin/env bash
# Fails unless every v5 role workflow pins the same host version and SHA-256s, and their
# install-host blocks are byte-identical.
#   check-workflow-pins.sh [--allow-unreleased]   (the flag accepts the all-zero hashes used before the first release)
set -euo pipefail
allow_unreleased=${1:-}
cd "$(dirname "$0")/../.github/workflows"
files=(rsolv-scan.yml rsolv-work.yml rsolv-publish.yml)
if [ "$allow_unreleased" != --allow-unreleased ] && grep -q '"0\{64\}"' "${files[@]}"; then
  echo "::error::a v5 workflow still pins the all-zero host SHA-256 (no host release is pinned)"
  exit 1
fi
for key in RSOLV_HOST_VERSION RSOLV_HOST_SHA256_X64 RSOLV_HOST_SHA256_ARM64; do
  n=$(grep -h "^ *$key:" "${files[@]}" | sed 's/^ *//' | sort -u | wc -l)
  [ "$n" -eq 1 ] || { echo "::error::$key differs across the v5 workflows"; exit 1; }
done
cat "${files[@]}" | grep -cE '^ *RSOLV_HOST_SHA256_(X64|ARM64): "[0-9a-f]{64}"$' | grep -qx 6 \
  || { echo "::error::a host SHA-256 is missing or malformed"; exit 1; }
cat "${files[@]}" | grep -cE '^ *RSOLV_HOST_VERSION: "[0-9]+\.[0-9]+\.[0-9]+"$' | grep -qx 3 \
  || { echo "::error::a host version is missing or malformed"; exit 1; }
n=$(for f in "${files[@]}"; do
  sed -n '/# BEGIN install-host/,/# END install-host/p' "$f" | grep -c . | grep -qv '^0$' || echo missing
  sed -n '/# BEGIN install-host/,/# END install-host/p' "$f" | sha256sum
done | sort -u | wc -l)
[ "$n" -eq 1 ] || { echo "::error::the install-host blocks differ across the v5 workflows (or one is missing)"; exit 1; }
