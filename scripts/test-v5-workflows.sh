#!/usr/bin/env bash
# Tests the v5 workflow tooling with no network: check-workflow-pins.sh, pin-host.sh and
# pin-sandbox.sh against a fake gh, check-first-parent.sh against a local repository,
# verify-sandbox-oci.sh against hand-built archives, and the host step of each role workflow
# against a fake curl and a stub host binary.
#   test-v5-workflows.sh        (needs bash, git, jq, yq and sha256sum; prints TAP-style lines, exits 1 on any failure)
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
fails=0
check() {
  local name=$1
  shift
  if "$@"; then echo "ok - $name"; else echo "not ok - $name"; fails=$((fails + 1)); fi
}
zero=$(printf '0%.0s' {1..64})

fresh_copy() {
  rm -rf "$t/r"
  mkdir -p "$t/r/.github" "$t/r/scripts"
  cp -r "$repo/.github/workflows" "$t/r/.github/"
  cp "$repo/scripts/"{check-workflow-pins,pin-host,pin-sandbox,check-first-parent,verify-sandbox-oci}.sh "$t/r/scripts/"
}
workflows_sum() { cat "$t/r/.github/workflows/"*.yml | sha256sum; }

# --- check-workflow-pins.sh ---------------------------------------------------------------
fresh_copy
pins=$t/r/scripts/check-workflow-pins.sh
check "pins: the unreleased placeholder passes with --allow-unreleased" "$pins" --allow-unreleased --allow-placeholder-keys
quietly() { "$@" >"$t/o" 2>&1; }
fails_saying() { ! "$@" >"$t/o" 2>&1 && grep -q -- "$want" "$t/o"; }
want=all-zero
check "pins: the unreleased placeholder fails without the flag" fails_saying "$pins"
sed -i -E "0,/RSOLV_HOST_SHA256_X64: /s/(RSOLV_HOST_SHA256_X64: )\"0/\1\"1/" "$t/r/.github/workflows/rsolv-work.yml"
want=RSOLV_HOST_SHA256_X64
check "pins: one changed hash fails, naming the key" fails_saying "$pins" --allow-unreleased --allow-placeholder-keys
fresh_copy
sed -i 's/--retry 3/--retry 4/' "$t/r/.github/workflows/rsolv-publish.yml"
want="install-host"
check "pins: a changed install-host block fails" fails_saying "$pins" --allow-unreleased --allow-placeholder-keys

# The template's calls: full commit SHAs, one commit; --strict also refuses the placeholder.
tpl=$t/r/.github/workflows/TEMPLATE-rsolv-v5.yml
real=$(printf 'a%.0s' {1..40})
fresh_copy
want="all-zero commit placeholder"
check "pins: --strict refuses the template's all-zero placeholder" fails_saying "$pins" --allow-unreleased --allow-placeholder-keys --strict
sed -i "s/@0\{40\}/@$real/" "$tpl"
check "pins: --strict accepts a template pinned to a real commit" "$pins" --allow-unreleased --allow-placeholder-keys --strict
sed -i "0,/@$real/s/@$real/@$(printf 'b%.0s' {1..40})/" "$tpl"
want="different commits"
check "pins: template calls at two commits fail" fails_saying "$pins" --allow-unreleased --allow-placeholder-keys
fresh_copy
sed -i "0,/@0\{40\}/s/@0\{40\}/@v5/" "$tpl"
want="full commit SHA"
check "pins: a template call by tag fails, even without --strict" fails_saying "$pins" --allow-unreleased --allow-placeholder-keys
fresh_copy
want=usage
check "pins: an unknown flag is refused" fails_saying "$pins" --allow-unreleasd

# Every pin name is its one job-level definition or a read inside install-host; no YAML
# indirection (anchors, aliases, merge keys, escapes, explicit keys, expression env) can hide one.
vw=$t/r/.github/workflows/rsolv-verify.yml
other=$(printf 'a%.0s' {1..64})
overridden() { # sed script applied to rsolv-verify.yml, then the check must fail naming $want
  fresh_copy
  sed -i "$1" "$vw"
  fails_saying "$pins" --allow-unreleased --allow-placeholder-keys
}
want="RSOLV_HOST_SHA256_X64"
# shellcheck disable=SC2016 # the workflow expands it
check "pins: a flow-style step env override is refused" overridden \
  "/^          ref: /a\\      - env: {RSOLV_HOST_SHA256_X64: \"$other\"}\\n        run: echo \"RSOLV_HOST_SHA256_X64=\$RSOLV_HOST_SHA256_X64\" >>\"\$GITHUB_ENV\""
check "pins: a block-style step env override is refused" overridden \
  "/^          ISSUE: /a\\          RSOLV_HOST_SHA256_X64: \"$other\""
check "pins: a second job-level definition is refused" overridden \
  "/^      RSOLV_HOST_SHA256_X64: /a\\      'RSOLV_HOST_SHA256_X64': \"$other\""
check "pins: an assignment inside install-host is refused" overridden \
  "/^          set -euo pipefail/a\\          RSOLV_HOST_SHA256_X64=$other"
want="YAML indirection"
check "pins: an anchor is refused" overridden 's/^    env:$/    env: \&pins/'
check "pins: a merge key is refused" overridden "/^          ISSUE: /a\\          <<: {}"
check "pins: an alias is refused" overridden 's/^          ISSUE: .*/          ISSUE: *issue/'
check "pins: a \\u escape is refused" overridden 's/^          ISSUE: .*/          "ISS\\u0055E": "7"/'
check "pins: an explicit key is refused" overridden "/^          ISSUE: /a\\          ? ISSUE2\\n          : x"
# shellcheck disable=SC2016 # a GitHub expression, not shell
check "pins: an expression as a whole env is refused" overridden \
  's/^        env:$/        env: ${{ fromJSON(inputs.env) }}/'
fresh_copy
check "pins: the unchanged workflows still pass" "$pins" --allow-unreleased --allow-placeholder-keys

# The decision key sets in rsolv-publish.yml (RFC-150 §6.4): the placeholders, or real sets of at
# least two unexpired keys within the 90-day cap, one line each, nowhere else.
pw=$t/r/.github/workflows/rsolv-publish.yml
key() { head -c 32 /dev/zero | tr '\0' "$1" | base64 -w0 | tr '+/' '-_' | tr -d '='; }
day() { date -u -d "$1" +%F; }
key_set() { # kid-prefix not_after key-fill-a key-fill-b
  printf '[{"kid":"%s-a","public_key":"%s","not_after":"%s"},{"kid":"%s-b","public_key":"%s","not_after":"%s"}]' \
    "$1" "$(key "$3")" "$2" "$1" "$(key "$4")" "$2"
}
prod_keys=$(key_set prod-x "$(day '+60 days')" 1 2)
staging_keys=$(key_set staging-x "$(day '+60 days')" 3 4)
set_keys() { sed -i "s|^\(          RSOLV_DECISION_KEYS_$1: \).*|\1$2|" "$pw"; }
released() { # a fresh copy with a real host pin and the given production set (staging real too)
  fresh_copy
  sed -i "s/\"$zero\"/\"$other\"/" "$t/r/.github/workflows/"rsolv-*.yml
  set_keys STAGING "'$staging_keys'"
  set_keys PRODUCTION "$1"
}
fresh_copy
sed -i "s/\"$zero\"/\"$other\"/" "$t/r/.github/workflows/"rsolv-*.yml
want="placeholder key set"
check "keys: the placeholder sets fail without --allow-placeholder-keys" fails_saying "$pins"
check "keys: the placeholder sets pass with --allow-placeholder-keys" "$pins" --allow-placeholder-keys
released "'$prod_keys'"
check "keys: real production and staging sets pass with no flag" "$pins"
want=RSOLV_DECISION_KEYS_PRODUCTION
refused_keys() { released "$1"; fails_saying "$pins" --allow-placeholder-keys; }
check "keys: a single key is refused" refused_keys "'${prod_keys%%\},*}}]'"
check "keys: an expired key is refused" refused_keys "'$(key_set prod-x "$(day yesterday)" 1 2)'"
check "keys: a not_after past the 90-day cap is refused" refused_keys "'$(key_set prod-x "$(day '+91 days')" 1 2)'"
check "keys: an all-zero key under a real kid is refused" refused_keys "'$(key_set prod-x "$(day '+60 days')" '\0' 2)'"
check "keys: a placeholder kid with a real key is refused" refused_keys "'${prod_keys/prod-x-a/unpinned-production-a}'"
check "keys: a duplicate kid is refused" refused_keys "'${prod_keys/prod-x-b/prod-x-a}'"
check "keys: JSON with spaces is refused" refused_keys "'${prod_keys//,\"/, \"}'"
# shellcheck disable=SC2016 # a GitHub expression, not shell
check "keys: an expression is refused" refused_keys '${{ inputs.decision_keys }}'
check "keys: the staging placeholder is refused" \
  refused_keys "'$(sed -n "s/^          RSOLV_DECISION_KEYS_STAGING: '\(.*\)'\$/\1/p" "$repo/.github/workflows/rsolv-publish.yml")'"
want="share a key"
check "keys: a key shared by production and staging is refused" refused_keys "'$(key_set prod-x "$(day '+60 days')" 3 2)'"
want=RSOLV_DECISION_KEYS_STAGING
released "'$prod_keys'"
sed -i '/^          RSOLV_DECISION_KEYS_STAGING: /d' "$pw"
check "keys: a missing staging set is refused" fails_saying "$pins" --allow-placeholder-keys
want=RSOLV_DECISION_KEYS_PRODUCTION
released "'$prod_keys'"
sed -i "/^          ISSUE: /a\\          RSOLV_DECISION_KEYS_PRODUCTION: '$prod_keys'" "$vw"
check "keys: a key set in another workflow is refused" fails_saying "$pins" --allow-placeholder-keys

# A local "main" with a merged branch, for check-first-parent.sh and the pin scripts.
origin=$t/origin
git init -q -b main "$origin"
gitc() { git -C "$origin" -c user.name=t -c user.email=t@t -c commit.gpgsign=false "$@"; }
gitc commit -q --allow-empty -m base
base=$(gitc rev-parse HEAD)
gitc checkout -q -b side
gitc commit -q --allow-empty -m side
side=$(gitc rev-parse HEAD)
gitc checkout -q main
gitc merge -q --no-ff -m merge side
merge=$(gitc rev-parse HEAD)
gitc checkout -q -b elsewhere
gitc commit -q --allow-empty -m unmerged
unmerged=$(gitc rev-parse HEAD)
gitc checkout -q main

# --- pin-host.sh, against a fake gh and the local main--------------------------------------------------------
mkdir -p "$t/bin" "$t/fake/assets"
cat >"$t/bin/gh" <<'EOF'
#!/usr/bin/env bash
f=$FAKE_GH
echo "gh $*" >>"$f/log"
case "$1 $2" in
  "--version "*) echo "gh version $(cat "$f/version") (2026-01-01)" ;;
  "release download")
    [ -f "$f/released" ] || { echo "release not found" >&2; exit 1; }
    while [ $# -gt 0 ]; do [ "$1" = --dir ] && dir=$2; shift; done
    cp "$f/assets/"* "$dir/" ;;
  "release verify") exit "$(cat "$f/release_rc")" ;;
  "attestation verify") rc=$(cat "$f/attest_rc"); [ "$rc" = 0 ] || echo "fake gh: verification failed" >&2; exit "$rc" ;;
  "api "*/commits/*) cat "$f/commit" ;;
  *) echo "fake gh: unexpected $*" >&2; exit 64 ;;
esac
EOF
chmod +x "$t/bin/gh"
printf 'x64 binary\n' >"$t/fake/assets/rsolv-host-linux-x86_64"
printf 'arm binary\n' >"$t/fake/assets/rsolv-host-linux-aarch64"
(cd "$t/fake/assets" && sha256sum rsolv-host-linux-x86_64 rsolv-host-linux-aarch64 >SHA256SUMS)
x64_sum=$(awk '$2 == "rsolv-host-linux-x86_64" {print $1}' "$t/fake/assets/SHA256SUMS")
arm_sum=$(awk '$2 == "rsolv-host-linux-aarch64" {print $1}' "$t/fake/assets/SHA256SUMS")

fake_gh() { # version released attest_rc release_rc tag_commit
  echo "$1" >"$t/fake/version"
  if [ "$2" = yes ]; then touch "$t/fake/released"; else rm -f "$t/fake/released"; fi
  echo "$3" >"$t/fake/attest_rc"
  echo "$4" >"$t/fake/release_rc"
  echo "$5" >"$t/fake/commit"
  : >"$t/fake/log"
}
pin() { PATH="$t/bin:$PATH" FAKE_GH="$t/fake" RSOLV_HOST_REMOTE="$origin" "$t/r/scripts/pin-host.sh" "$@" >"$t/pin.out" 2>&1; }
refuses_unchanged() { # name, then pin-host args
  local name=$1 before
  shift
  fresh_copy
  before=$(workflows_sum)
  check "pin-host: $name is refused" bash -c '! pin "$@"' _ "$@"
  check "pin-host: $name changes no workflow" test "$before" = "$(workflows_sum)"
}
export -f pin
export t origin

fake_gh 2.102.0 yes 0 0 "$merge"
refuses_unchanged "a malformed version" 0.1
fake_gh 2.101.9 yes 0 0 "$merge"
refuses_unchanged "a gh older than 2.102.0" 0.1.0
fake_gh 2.102.0 no 0 0 "$merge"
refuses_unchanged "a missing release" 0.0.0
fake_gh 2.102.0 yes 1 0 "$merge"
refuses_unchanged "a failed attestation (a PR dry run's, say)" 0.1.0
fake_gh 2.102.0 yes 0 1 "$merge"
refuses_unchanged "a failed release verification" 0.1.0
fake_gh 2.102.0 yes 0 0 "$side"
refuses_unchanged "a tag on a commit from inside a merged branch" 0.1.0
check "pin-host: the merged-branch tag is refused as not first-parent" grep -q "not a first-parent commit of $origin main" "$t/pin.out"
fake_gh 2.102.0 yes 0 0 "$unmerged"
refuses_unchanged "a tag on a commit off main" 0.1.0
fake_gh 2.102.0 yes 0 0 "$merge"
printf 'tampered\n' >>"$t/fake/assets/rsolv-host-linux-aarch64"
refuses_unchanged "an asset that doesn't match SHA256SUMS" 0.1.0
printf 'arm binary\n' >"$t/fake/assets/rsolv-host-linux-aarch64"

fake_gh 2.102.0 yes 0 0 "$merge"
fresh_copy
check "pin-host: a verified release is pinned" pin 0.1.0
wf=$t/r/.github/workflows
check "pin-host: the x64 SHA-256 is written to all four role workflows" \
  test "$(cat "$wf"/rsolv-{scan,work,verify,publish}.yml | grep -c "RSOLV_HOST_SHA256_X64: \"$x64_sum\"")" -eq 4
check "pin-host: the arm64 SHA-256 is written to all four role workflows" \
  test "$(cat "$wf"/rsolv-{scan,work,verify,publish}.yml | grep -c "RSOLV_HOST_SHA256_ARM64: \"$arm_sum\"")" -eq 4
check "pin-host: the version is written" \
  test "$(cat "$wf"/rsolv-{scan,work,verify,publish}.yml | grep -c 'RSOLV_HOST_VERSION: "0.1.0"')" -eq 4
check "pin-host: the pinned workflows pass the pin check without --allow-unreleased" \
  "$t/r/scripts/check-workflow-pins.sh" --allow-placeholder-keys
check "pin-host: the tag commit is resolved through refs/tags/" \
  grep -q 'gh api repos/RSOLV-dev/rsolv-host/commits/refs/tags/host-v0.1.0 --jq .sha' "$t/fake/log"
want="--repo RSOLV-dev/rsolv-host --signer-workflow RSOLV-dev/rsolv-host/.github/workflows/host-release.yml"
want="$want --source-ref refs/tags/host-v0.1.0 --source-digest $merge --deny-self-hosted-runners"
check "pin-host: each binary is verified with the exact provenance flags" \
  test "$(grep -c -- "attestation verify .*/rsolv-host-linux-[a-z0-9_]* $want\$" "$t/fake/log")" -eq 2

# --- the host step of each role workflow, against a fake curl and a stub host -----------------
cat >"$t/bin/curl" <<'EOF'
#!/usr/bin/env bash
while [ $# -gt 0 ]; do [ "$1" = -o ] && out=$2; url=$1; shift; done
echo "$url" >>"$STUB_DIR/curl.log"
cp "$STUB_DIR/stub" "$out"
EOF
cat >"$t/bin/sleep" <<'EOF'
#!/bin/sh
echo "sleep $*" >>"$STUB_DIR/curl.log"
EOF
chmod +x "$t/bin/curl" "$t/bin/sleep"
mkdir -p "$t/stub"
# The stub sees only what env -i passed, so it logs under RUNNER_TEMP. It exits with the next
# code from rcs (default 0), and on `version` it can modify itself to test re-verification.
cat >"$t/stub/stub" <<'EOF'
#!/bin/sh
log="$RUNNER_TEMP/calls"
{ echo "ARGS $*"; tr '\0' '\n' </proc/$$/environ | sed 's/=.*//' | sort | sed 's/^/ENV /'; } >>"$log"
if [ "$1" = version ]; then
  [ -f "$RUNNER_TEMP/tamper" ] && chmod u+w "$0" && echo tampered >>"$0"
  echo "INSTALL $RSOLV_HOST_INSTALL_DIR" >>"$log"
  exit 0
fi
echo "KEYS ${RSOLV_DECISION_KEYS-}" >>"$log"
rcs=$(cat "$RUNNER_TEMP/rcs" 2>/dev/null)
rc=${rcs%% *}
echo "${rcs#"$rc"}" | sed 's/^ //' >"$RUNNER_TEMP/rcs"
# Each role's own success outcome: work's mitigated, verify's verified.
case $1 in verify) outcome=verified ;; *) outcome=mitigated ;; esac
[ "${rc:-0}" -eq 0 ] && echo "outcome=$outcome" >>"$GITHUB_OUTPUT"
exit "${rc:-0}"
EOF
stub_sum=$(sha256sum "$t/stub/stub" | cut -d' ' -f1)

host_step() { # workflow job -> the host step's script
  yq -r ".jobs.$2.steps[] | select(.id == \"host\") | .run" "$repo/.github/workflows/$1"
}
run_step() { # workflow job sha rcs [VAR=value ...]; sets $rc, $rt (RUNNER_TEMP)
  local workflow=$1 job=$2 sum=$3 rcs=$4
  shift 4
  rt=$(mktemp -d "$t/rt.XXXXXX")
  echo "$rcs" >"$rt/rcs"
  : >"$rt/out"
  host_step "$workflow" "$job" >"$rt/step.sh"
  rc=0
  env PATH="$t/bin:$PATH" STUB_DIR="$t/stub" RUNNER_OS=Linux RUNNER_ARCH=X64 RUNNER_TEMP="$rt" \
    RSOLV_HOST_VERSION=0.1.0 RSOLV_HOST_SHA256_X64="$sum" RSOLV_HOST_SHA256_ARM64="$zero" \
    GITHUB_OUTPUT="$rt/out" GITHUB_STEP_SUMMARY="$rt/summary" GITHUB_REPOSITORY=o/r GITHUB_REPOSITORY_ID=1 \
    GITHUB_RUN_ID=2 GITHUB_RUN_ATTEMPT=1 GITHUB_WORKSPACE="$rt" GITHUB_API_URL=https://api.github.com \
    GITHUB_GRAPHQL_URL=https://api.github.com/graphql ACTIONS_ID_TOKEN_REQUEST_URL=https://oidc \
    ACTIONS_ID_TOKEN_REQUEST_TOKEN=oidc-secret GITHUB_TOKEN=ghs_secret RSOLV_API_URL=https://api.rsolv.ai. \
    ERL_AFLAGS="-eval halt()" LD_PRELOAD=/evil.so RSOLV_HOST_INSTALL_DIR="$t/caller-tree" \
    ISSUE=7 MAX_ISSUES=5 RSOLV_DECISION_KEYS_PRODUCTION="$prod_keys" RSOLV_DECISION_KEYS_STAGING="$staging_keys" \
    EXACT_RUNTIME_VERSIONS=false "$@" \
    bash -e "$rt/step.sh" >"$rt/stdout" 2>&1 || rc=$?
}
calls() { grep -c '^ARGS' "$rt/calls" 2>/dev/null || echo 0; }
nth_args() { grep '^ARGS' "$rt/calls" | sed -n "${1}p"; }
env_of() { awk -v n="$1" '/^ARGS/ {i++} i == n && /^ENV / {print $2}' "$rt/calls" | sort | tr '\n' ' '; }
: >"$t/stub/curl.log"

for spec in rsolv-scan.yml:scan rsolv-work.yml:work rsolv-verify.yml:verify rsolv-publish.yml:publish; do
  wf=${spec%%:*} job=${spec#*:}
  run_step "$wf" "$job" "$zero" ""
  check "$job: an all-zero pin exits 2 before any download" test "$rc" -eq 2
  check "$job: the all-zero refusal says why" grep -q 'pins no rsolv-host release' "$rt/stdout"
  check "$job: nothing ran" test "$(calls)" -eq 0
  run_step "$wf" "$job" "$(printf 'f%.0s' {1..64})" ""
  check "$job: a SHA-256 mismatch fails and never runs the binary" bash -c "[ $rc -ne 0 ] && [ $(calls) -eq 0 ]"
  run_step "$wf" "$job" "$stub_sum" ""
  check "$job: a verified binary runs and the step exits 0" test "$rc" -eq 0
  check "$job: the first call is \`version\`, alone" test "$(nth_args 1)" = "ARGS version"
  check "$job: \`version\` gets only the base environment" \
    test "$(env_of 1)" = "HOME LANG PATH RSOLV_HOST_INSTALL_DIR RUNNER_TEMP "
  install=$(sed -n 's/^INSTALL //p' "$rt/calls")
  check "$job: the install dir is a fresh directory under RUNNER_TEMP, not the caller's" \
    bash -c "[[ '$install' == '$rt'/rsolv-host.* ]] && [ -d '$install' ]"
  check "$job: no ERL_* or LD_* reaches the host" bash -c "! grep -qE '^ENV (ERL_|LD_)' '$rt/calls'"
done

# Re-verification: this stub modifies itself on `version`, so the role command must not run.
tamper_step() {
  local wf=$1 job=$2
  # shellcheck disable=SC2016 # the stub expands it
  sed -i '2i touch "$RUNNER_TEMP/tamper"' "$t/stub/stub"
  local sum
  sum=$(sha256sum "$t/stub/stub" | cut -d' ' -f1)
  run_step "$wf" "$job" "$sum" ""
  sed -i '2d' "$t/stub/stub"
}
for spec in rsolv-scan.yml:scan rsolv-work.yml:work rsolv-verify.yml:verify rsolv-publish.yml:publish; do
  wf=${spec%%:*} job=${spec#*:}
  tamper_step "$wf" "$job"
  check "$job: a binary changed after \`version\` is refused before the role command" \
    bash -c "[ $rc -eq 4 ] && [ $(calls) -eq 1 ]"
done

run_step rsolv-scan.yml scan "$stub_sum" ""
check "scan: runs \`scan --max-issues\` with the input" test "$(nth_args 2)" = "ARGS scan --max-issues 5"
check "scan: gets GITHUB_TOKEN and the OIDC request variables" \
  bash -c "grep -q ' GITHUB_TOKEN ' <<<' $(env_of 2)' && grep -q ' ACTIONS_ID_TOKEN_REQUEST_TOKEN ' <<<' $(env_of 2)'"

run_step rsolv-publish.yml publish "$stub_sum" ""
check "publish: runs \`publish --issue\`" test "$(nth_args 2)" = "ARGS publish --issue 7"
check "publish: gets GITHUB_TOKEN and RSOLV_DECISION_KEYS" \
  bash -c "grep -q ' GITHUB_TOKEN ' <<<' $(env_of 2)' && grep -q ' RSOLV_DECISION_KEYS ' <<<' $(env_of 2)'"
check "publish: the production URL gets the production keys" grep -qxF "KEYS $prod_keys" "$rt/calls"
check "publish: no key set variable reaches the host" bash -c "! grep -q '^ENV RSOLV_DECISION_KEYS_' '$rt/calls'"
run_step rsolv-publish.yml publish "$stub_sum" "" RSOLV_API_URL=https://api.rsolv.dev.
check "publish: the rsolv.dev URL gets the production keys" grep -qxF "KEYS $prod_keys" "$rt/calls"
run_step rsolv-publish.yml publish "$stub_sum" "" RSOLV_API_URL=https://api.rsolv-staging.com.
check "publish: the staging URL gets the staging keys" grep -qxF "KEYS $staging_keys" "$rt/calls"
run_step rsolv-publish.yml publish "$stub_sum" "" RSOLV_API_URL=https://api.example.com.
check "publish: any other URL exits 2 before the role runs" bash -c "[ $rc -eq 2 ] && [ $(calls) -eq 1 ]"
placeholder=$(sed -n "s/^          RSOLV_DECISION_KEYS_PRODUCTION: '\(.*\)'\$/\1/p" "$repo/.github/workflows/rsolv-publish.yml")
run_step rsolv-publish.yml publish "$stub_sum" "" RSOLV_DECISION_KEYS_PRODUCTION="$placeholder"
check "publish: the placeholder key set exits 2 before the role runs" bash -c "[ $rc -eq 2 ] && [ $(calls) -eq 1 ]"
check "publish: the placeholder refusal says why" grep -q 'pins no decision keys' "$rt/stdout"
run_step rsolv-publish.yml publish "$stub_sum" "" RSOLV_DECISION_KEYS_PRODUCTION="$(key_set prod-x "$(day '+60 days')" '\0' 2)"
check "publish: a set with an all-zero key exits 2 before the role runs" bash -c "[ $rc -eq 2 ] && [ $(calls) -eq 1 ]"

run_step rsolv-work.yml work "$stub_sum" "0"
check "work: runs \`work --issue\`" test "$(nth_args 2)" = "ARGS work --issue 7"
check "work: gets no GITHUB_TOKEN" bash -c "! grep -q ' GITHUB_TOKEN ' <<<' $(env_of 2)'"
check "work: the host's outputs reach GITHUB_OUTPUT" grep -qx 'outcome=mitigated' "$rt/out"
check "work: no exact-runtime opt-in by default" bash -c "! grep -q RSOLV_EXACT_RUNTIME_VERSIONS <<<'$(env_of 2)'"
run_step rsolv-work.yml work "$stub_sum" "0" EXACT_RUNTIME_VERSIONS=true
check "work: the exact-runtime opt-in reaches the host" grep -q 'RSOLV_EXACT_RUNTIME_VERSIONS' <<<"$(env_of 2)"
run_step rsolv-work.yml work "$stub_sum" "3 0"
check "work: exit 3 then 0 retries once with --resume and exits 0" \
  bash -c "[ $rc -eq 0 ] && [ $(calls) -eq 3 ] && [ '$(nth_args 3)' = 'ARGS work --issue 7 --resume' ]"
check "work: the retry is announced" grep -q '::warning title=RSOLV::' "$rt/stdout"
run_step rsolv-work.yml work "$stub_sum" "3 3"
check "work: exit 3 twice retries only once and exits 3" bash -c "[ $rc -eq 3 ] && [ $(calls) -eq 3 ]"
for code in 1 2 4; do
  run_step rsolv-work.yml work "$stub_sum" "$code 0"
  check "work: exit $code is not retried" bash -c "[ $rc -eq $code ] && [ $(calls) -eq 2 ]"
done

run_step rsolv-verify.yml verify "$stub_sum" "0"
check "verify: runs \`verify --issue\`" test "$(nth_args 2)" = "ARGS verify --issue 7"
check "verify: gets no GITHUB_TOKEN" bash -c "! grep -q ' GITHUB_TOKEN ' <<<' $(env_of 2)'"
check "verify: gets the run attempt, the repository and the OIDC request variables" \
  bash -c "for v in GITHUB_RUN_ATTEMPT GITHUB_REPOSITORY GITHUB_WORKSPACE RUNNER_TEMP ACTIONS_ID_TOKEN_REQUEST_TOKEN; do grep -q \" \$v \" <<<' $(env_of 2)' || exit 1; done"
valid_verify_outcome() { # exactly one outcome line, and it is one of verify's
  [ "$(grep -c '^outcome=' "$1")" -eq 1 ] && grep -qxE 'outcome=(verified|verify_failed|rejected)' "$1"
}
check "verify: the host's outputs reach GITHUB_OUTPUT" grep -qx 'outcome=verified' "$rt/out"
check "verify: the outcome is one of verify's" valid_verify_outcome "$rt/out"
printf 'outcome=mitigated\n' >"$t/bad-outcome"
check "verify: work's outcome is not one of verify's" bash -c "$(declare -f valid_verify_outcome); ! valid_verify_outcome '$t/bad-outcome'"
check "verify: no exact-runtime opt-in by default" bash -c "! grep -q RSOLV_EXACT_RUNTIME_VERSIONS <<<'$(env_of 2)'"
run_step rsolv-verify.yml verify "$stub_sum" "0" EXACT_RUNTIME_VERSIONS=true
check "verify: the exact-runtime opt-in reaches the host" grep -q 'RSOLV_EXACT_RUNTIME_VERSIONS' <<<"$(env_of 2)"
for code in 1 2 3 4; do
  run_step rsolv-verify.yml verify "$stub_sum" "$code 0"
  check "verify: exit $code is not retried" bash -c "[ $rc -eq $code ] && [ $(calls) -eq 2 ]"
done

# --- check-first-parent.sh, against a local "main" with a merged branch ------------------------
first_parent() { RSOLV_ACTION_REMOTE=$origin "$t/r/scripts/check-first-parent.sh" "$@"; }
fresh_copy
check "first-parent: main's merge commit passes" quietly first_parent "$merge"
check "first-parent: main's earlier commit passes" quietly first_parent "$base"
want="not a first-parent commit"
check "first-parent: a commit from inside a merged branch fails" fails_saying first_parent "$side"
check "first-parent: a commit on another branch fails" fails_saying first_parent "$unmerged"
check "first-parent: an unknown commit fails" fails_saying first_parent "$(printf 'c%.0s' {1..40})"
first_parent abc >/dev/null 2>&1 && rc=0 || rc=$?
check "first-parent: a malformed SHA exits 2" test "$rc" -eq 2

# --- verify-sandbox-oci.sh, against hand-built OCI archives -------------------------------------
oci() { # dir arch [manifest bytes]; writes $1.tar, prints the manifest digest
  local d=$1 arch=$2 body=${3:-'{"schemaVersion":2,"config":{"digest":"sha256:00"}}'} hex
  rm -rf "$d" && mkdir -p "$d/blobs/sha256"
  hex=$(printf '%s' "$body" | sha256sum | cut -d' ' -f1)
  printf '%s' "$body" >"$d/blobs/sha256/$hex"
  jq -n --arg d "sha256:$hex" --arg a "$arch" \
    '{schemaVersion: 2, manifests: [{mediaType: "application/vnd.oci.image.manifest.v1+json", digest: $d, size: 1, platform: {os: "linux", architecture: $a}}]}' \
    >"$d/index.json"
  tar -cf "$d.tar" -C "$d" index.json blobs
  echo "sha256:$hex"
}
voci=$t/r/scripts/verify-sandbox-oci.sh
good=$(oci "$t/oci" amd64)
check "oci: a one-manifest archive prints its digest" test "$("$voci" "$t/oci.tar" amd64)" = "$good"
check "oci: the expected digest matches" quietly "$voci" "$t/oci.tar" amd64 "$good"
want="expected sha256"
check "oci: another expected digest fails" fails_saying "$voci" "$t/oci.tar" amd64 "sha256:$(printf 'd%.0s' {1..64})"
want="linux/arm64"
check "oci: the wrong architecture fails" fails_saying "$voci" "$t/oci.tar" arm64
printf 'x' >>"$t/oci/blobs/sha256/${good#sha256:}"
tar -cf "$t/oci.tar" -C "$t/oci" index.json blobs
want="doesn't hash"
check "oci: a manifest blob that doesn't hash to its digest fails" fails_saying "$voci" "$t/oci.tar" amd64
oci "$t/oci" amd64 >/dev/null
jq '.manifests += .manifests' "$t/oci/index.json" >"$t/i" && mv "$t/i" "$t/oci/index.json"
tar -cf "$t/oci.tar" -C "$t/oci" index.json blobs
want="exactly one"
check "oci: two manifests fail" fails_saying "$voci" "$t/oci.tar" amd64

# --- pin-sandbox.sh, against a fake gh and a fake rsolv-host checkout ------------------------------
idx="sha256:$(printf 'e%.0s' {1..64})"
fake_host() {
  rm -rf "$t/host" && mkdir -p "$t/host/rsolv_host/config"
  # shellcheck disable=SC2016 # Elixir, not shell
  printf '%s\n' 'config :rsolv_host,' '  proxy_image: "squid",' \
    '  sandbox_image: "ghcr.io/rsolv-dev/rsolv-sandbox@sha256:" <> String.duplicate("0", 64)' '' 'import_config "x"' \
    >"$t/host/rsolv_host/config/config.exs"
}
pin_sandbox() { PATH="$t/bin:$PATH" FAKE_GH="$t/fake" RSOLV_ACTION_REMOTE="$origin" "$t/r/scripts/pin-sandbox.sh" "$@"; }
sandbox_refused() { # name, expected message, then pin-sandbox args
  local name=$1 before
  want=$2
  shift 2
  fresh_copy
  fake_host
  before=$(sha256sum <"$t/host/rsolv_host/config/config.exs")
  check "pin-sandbox: $name is refused" fails_saying pin_sandbox "$@"
  check "pin-sandbox: $name changes nothing" test "$before" = "$(sha256sum <"$t/host/rsolv_host/config/config.exs")"
}
fake_gh 2.102.0 yes 0 0 "$merge"
echo "$merge" >"$t/fake/commit"
sandbox_refused "a malformed version" usage 0.1 "$idx" "$t/host"
sandbox_refused "a malformed digest" usage 0.1.0 "sha256:abc" "$t/host"
sandbox_refused "the all-zero digest" all-zero 0.1.0 "sha256:$zero" "$t/host"
sandbox_refused "a checkout without config.exs" "no single sandbox_image" 0.1.0 "$idx" "$t/nowhere"
fake_gh 2.101.9 yes 0 0 "$merge"
echo "$merge" >"$t/fake/commit"
sandbox_refused "a gh older than 2.102.0" "older than 2.102.0" 0.1.0 "$idx" "$t/host"
fake_gh 2.102.0 yes 0 0 "$merge"
echo "$side" >"$t/fake/commit"
sandbox_refused "a tag on a commit from inside a merged branch" "not a first-parent commit" 0.1.0 "$idx" "$t/host"
fake_gh 2.102.0 yes 1 0 "$merge"
echo "$merge" >"$t/fake/commit"
sandbox_refused "a failed attestation" "verification failed" 0.1.0 "$idx" "$t/host"

fake_gh 2.102.0 yes 0 0 "$merge"
echo "$merge" >"$t/fake/commit"
fresh_copy
fake_host
check "pin-sandbox: a verified release is pinned" quietly pin_sandbox 0.1.0 "$idx" "$t/host"
# mix format's own shape: a real digest makes the one-line form too long, so the key and the
# string sit on two lines.
pinned_as() { # config, digest: the key alone on its line, the string on the next, nothing else changed
  [ "$(grep -c . "$1")" = 5 ] && [ "$(grep -cx '  sandbox_image:' "$1")" = 1 ] &&
    [ "$(grep -A1 -x '  sandbox_image:' "$1" | tail -n 1)" = "    \"ghcr.io/rsolv-dev/rsolv-sandbox@$2\"" ]
}
check "pin-sandbox: the digest is written to sandbox_image as mix format lays it out, and nothing else changes" \
  pinned_as "$t/host/rsolv_host/config/config.exs" "$idx"
idx2="sha256:$(printf 'f%.0s' {1..64})"
check "pin-sandbox: a pinned checkout can be re-pinned" quietly pin_sandbox 0.1.0 "$idx2" "$t/host"
check "pin-sandbox: a re-pin replaces the digest in place" pinned_as "$t/host/rsolv_host/config/config.exs" "$idx2"
check "pin-sandbox: the tag commit is resolved through refs/tags/" \
  grep -q 'gh api repos/RSOLV-dev/rsolv-action/commits/refs/tags/sandbox-v0.1.0 --jq .sha' "$t/fake/log"
want="gh attestation verify oci://ghcr.io/rsolv-dev/rsolv-sandbox@$idx --repo RSOLV-dev/rsolv-action"
want="$want --signer-workflow RSOLV-dev/rsolv-action/.github/workflows/sandbox-image.yml"
want="$want --source-ref refs/tags/sandbox-v0.1.0 --source-digest $merge --deny-self-hosted-runners"
check "pin-sandbox: the index digest is verified with the exact provenance flags" grep -qxF -- "$want" "$t/fake/log"

[ "$fails" -eq 0 ] || { echo "$fails test(s) failed"; exit 1; }
echo "all passed"
