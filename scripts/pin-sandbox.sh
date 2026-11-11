#!/usr/bin/env bash
# Pins a sandbox image release into an rsolv-host checkout (rsolv_host/config/config.exs), only
# after its provenance verifies (docs/V5-RELEASE.md, "Pinning the sandbox image"). Writes nothing
# until every check has passed.
#   pin-sandbox.sh <version> <sha256:index digest> <rsolv-host checkout>
#   e.g. pin-sandbox.sh 0.1.0 sha256:4f…e1 ../rsolv-host
set -euo pipefail
version=${1:-} digest=${2:-} host=${3:-}
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && $digest =~ ^sha256:[0-9a-f]{64}$ && -n $host ]] ||
  { echo "usage: pin-sandbox.sh <version> <sha256:digest> <rsolv-host checkout>" >&2; exit 2; }
[[ $digest =~ ^sha256:0{64}$ ]] && { echo "::error::the all-zero digest is the placeholder, not a release" >&2; exit 2; }
config=$host/rsolv_host/config/config.exs
[ "$(grep -cE '^ *sandbox_image:( |$)' "$config" 2>/dev/null)" = 1 ] ||
  { echo "::error::$config has no single sandbox_image line" >&2; exit 2; }
here=$(cd "$(dirname "$0")" && pwd)
repo=RSOLV-dev/rsolv-action
image=ghcr.io/rsolv-dev/rsolv-sandbox
tag="sandbox-v$version"
gh() { env -u GITHUB_TOKEN gh "$@"; }

# 1. A gh older than 2.102.0 can pass attestations these flags are meant to reject.
have=$(gh --version | awk 'NR == 1 {print $3}')
printf '%s\n' 2.102.0 "$have" | sort -V -C || { echo "::error::gh $have is older than 2.102.0" >&2; exit 2; }

# 2. The tag's commit, through refs/tags/ so a branch of the same name can't stand in, is a
#    first-parent commit of main.
commit=$(gh api "repos/$repo/commits/refs/tags/$tag" --jq .sha)
[[ $commit =~ ^[0-9a-f]{40}$ ]] || { echo "::error::could not resolve $tag to a commit" >&2; exit 1; }
"$here/check-first-parent.sh" "$commit"

# 3. Provenance of the index digest. --source-ref and --source-digest bind it to this tag and
#    commit; --signer-workflow to sandbox-image.yml, whose publish job alone attests.
gh attestation verify "oci://$image@$digest" --repo "$repo" \
  --signer-workflow "$repo/.github/workflows/sandbox-image.yml" \
  --source-ref "refs/tags/$tag" \
  --source-digest "$commit" \
  --deny-self-hosted-runners

# 4. Only now write the pin.
#    As mix format lays it out: a real digest makes the one-line form too long, so the key ends
#    its line and the string follows. It replaces either form: a value on the key's line (the
#    placeholder), or a quoted string alone on the next line (an earlier pin). Anything else is
#    refused. The result is checked whole, before it replaces config.exs: everything but the
#    pin is unchanged.
pin="    \"$image@$digest\""
strip() { # the file without its sandbox_image entry, in either form
  awk 'value { value = 0; if ($0 ~ /^[ \t]+"[^"]*"[ \t]*$/) next }
    /^ *sandbox_image:/ { value = ($0 ~ /^ *sandbox_image:[ \t]*$/); next }
    { print }' "$1"
}
out=$(mktemp)
if ! awk -v pin="$pin" '
  value { value = 0; if ($0 ~ /^[ \t]+"[^"]*"[ \t]*$/) next; bad = 1 }
  /^ *sandbox_image:/ {
    if ($0 ~ /^ *sandbox_image:[ \t]*$/) value = 1
    else if ($0 !~ /^ *sandbox_image:[ \t]+[^ \t]/) bad = 1
    print "  sandbox_image:"; print pin; next
  }
  { print }
  END { exit (bad || value) }' "$config" >"$out" ||
  [ "$(grep -A1 -x '  sandbox_image:' "$out" | tail -n 1)" != "$pin" ] ||
  ! cmp -s <(strip "$config") <(strip "$out"); then
  rm -f "$out"; echo "::error::the pin wasn't written" >&2; exit 1
fi
cat "$out" >"$config" && rm -f "$out"
echo "pinned $tag ($commit): $image@$digest"
