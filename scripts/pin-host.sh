#!/usr/bin/env bash
# Pins an rsolv-host release into the v5 role workflows, only after its provenance verifies
# (rsolv-host docs/RELEASE-RUNBOOK.md, "The pin script's contract"). Writes nothing until every
# check has passed.
#   pin-host.sh <version>        e.g. pin-host.sh 0.1.0
set -euo pipefail
version=${1:-}
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "usage: pin-host.sh <version>, e.g. 0.1.0" >&2; exit 2; }
here=$(cd "$(dirname "$0")" && pwd)
repo=RSOLV-dev/rsolv-host
tag="host-v$version"
gh() { env -u GITHUB_TOKEN gh "$@"; }

# 1. A gh older than 2.102.0 can pass attestations these flags are meant to reject.
have=$(gh --version | awk 'NR == 1 {print $3}')
printf '%s\n' 2.102.0 "$have" | sort -V -C || { echo "::error::gh $have is older than 2.102.0" >&2; exit 2; }

# 2. Download into a fresh directory and check the release's own SHA256SUMS.
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
gh release download "$tag" --repo "$repo" --dir "$dir"
(cd "$dir" && sha256sum -c SHA256SUMS)

# 3. The tag's commit, through refs/tags/ so a branch of the same name can't stand in, is a
#    first-parent commit of main: not one from inside a merged branch (RSOLV_HOST_REMOTE
#    overrides the remote, for tests).
commit=$(gh api "repos/$repo/commits/refs/tags/$tag" --jq .sha)
[[ $commit =~ ^[0-9a-f]{40}$ ]] || { echo "::error::could not resolve $tag to a commit" >&2; exit 1; }
RSOLV_ACTION_REMOTE=${RSOLV_HOST_REMOTE:-https://github.com/$repo.git} "$here/check-first-parent.sh" "$commit"

# 4. Provenance. --source-ref and --source-digest reject a pull request's dry-run attestation,
#    which the same signer workflow makes from refs/pull/<n>/merge.
for asset in rsolv-host-linux-x86_64 rsolv-host-linux-aarch64; do
  gh attestation verify "$dir/$asset" --repo "$repo" \
    --signer-workflow "$repo/.github/workflows/host-release.yml" \
    --source-ref "refs/tags/$tag" \
    --source-digest "$commit" \
    --deny-self-hosted-runners
done

# 5. The release itself is immutable and attested.
gh release verify "$tag" --repo "$repo"

# 6. Only now write the pins, from the verified SHA256SUMS.
x64=$(awk '$2 == "rsolv-host-linux-x86_64" {print $1}' "$dir/SHA256SUMS")
arm=$(awk '$2 == "rsolv-host-linux-aarch64" {print $1}' "$dir/SHA256SUMS")
[[ $x64 =~ ^[0-9a-f]{64}$ && $arm =~ ^[0-9a-f]{64}$ ]] || { echo "::error::SHA256SUMS lacks a binary" >&2; exit 1; }
cd "$here/../.github/workflows"
sed -i -E \
  -e "s/^( *RSOLV_HOST_VERSION: ).*/\\1\"$version\"/" \
  -e "s/^( *RSOLV_HOST_SHA256_X64: ).*/\\1\"$x64\"/" \
  -e "s/^( *RSOLV_HOST_SHA256_ARM64: ).*/\\1\"$arm\"/" \
  rsolv-scan.yml rsolv-work.yml rsolv-verify.yml rsolv-publish.yml
# The decision key sets are pinned on their own schedule (the key ceremony); CI refuses their
# placeholders once real keys land.
"$here/check-workflow-pins.sh" --allow-placeholder-keys
echo "pinned $tag ($commit): x86_64 $x64, aarch64 $arm"
