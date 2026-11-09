#!/usr/bin/env bash
# Fails unless every v5 role workflow pins the same host version and SHA-256s, their
# install-host blocks are byte-identical, and the customer template calls them by one full
# commit SHA.
#   check-workflow-pins.sh [--allow-unreleased] [--strict]
#     --allow-unreleased  accepts the all-zero host hashes used before the first host release
#     --strict            refuses the template's all-zero commit placeholder (from the first v5 release)
set -euo pipefail
allow_unreleased='' strict=''
for arg in "$@"; do
  case $arg in
    --allow-unreleased) allow_unreleased=1 ;;
    --strict) strict=1 ;;
    *) echo "usage: check-workflow-pins.sh [--allow-unreleased] [--strict]" >&2; exit 2 ;;
  esac
done
cd "$(dirname "$0")/../.github/workflows"
files=(rsolv-scan.yml rsolv-work.yml rsolv-verify.yml rsolv-publish.yml)
if [ -z "$allow_unreleased" ] && grep -q '"0\{64\}"' "${files[@]}"; then
  echo "::error::a v5 workflow still pins the all-zero host SHA-256 (no host release is pinned)"
  exit 1
fi
for key in RSOLV_HOST_VERSION RSOLV_HOST_SHA256_X64 RSOLV_HOST_SHA256_ARM64; do
  n=$(grep -h "^ *$key:" "${files[@]}" | sed 's/^ *//' | sort -u | wc -l)
  [ "$n" -eq 1 ] || { echo "::error::$key differs across the v5 workflows"; exit 1; }
done
cat "${files[@]}" | grep -cE '^ *RSOLV_HOST_SHA256_(X64|ARM64): "[0-9a-f]{64}"$' | grep -qx 8 \
  || { echo "::error::a host SHA-256 is missing or malformed"; exit 1; }
cat "${files[@]}" | grep -cE '^ *RSOLV_HOST_VERSION: "[0-9]+\.[0-9]+\.[0-9]+"$' | grep -qx 4 \
  || { echo "::error::a host version is missing or malformed"; exit 1; }
n=$(for f in "${files[@]}"; do
  sed -n '/# BEGIN install-host/,/# END install-host/p' "$f" | grep -c . | grep -qv '^0$' || echo missing
  sed -n '/# BEGIN install-host/,/# END install-host/p' "$f" | sha256sum
done | sort -u | wc -l)
[ "$n" -eq 1 ] || { echo "::error::the install-host blocks differ across the v5 workflows (or one is missing)"; exit 1; }

template=TEMPLATE-rsolv-v5.yml
uses=$(grep -E '^ *uses:' "$template" | sed -E 's/^ *uses: *//; s/ *#.*//')
[ -n "$uses" ] || { echo "::error::$template calls no reusable workflow"; exit 1; }
grep -vqE '^RSOLV-dev/rsolv-action/\.github/workflows/rsolv-[a-z]+\.yml@[0-9a-f]{40}$' <<<"$uses" &&
  { echo "::error::$template calls a workflow by something other than a full commit SHA"; exit 1; }
[ "$(cut -d@ -f2 <<<"$uses" | sort -u | wc -l)" -eq 1 ] ||
  { echo "::error::$template calls the workflows at different commits"; exit 1; }
if [ -n "$strict" ] && grep -qE '@0{40}$' <<<"$uses"; then
  echo "::error::$template still calls the all-zero commit placeholder (no v5 release is pinned)"
  exit 1
fi
