#!/usr/bin/env bash
# Tests the v5 workflow tooling with no network: check-workflow-pins.sh, pin-host.sh against a
# fake gh, and the host step of each role workflow against a fake curl and a stub host binary.
#   test-v5-workflows.sh        (needs bash, yq and sha256sum; prints TAP-style lines, exits 1 on any failure)
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
  cp "$repo/scripts/check-workflow-pins.sh" "$repo/scripts/pin-host.sh" "$t/r/scripts/"
}
workflows_sum() { cat "$t/r/.github/workflows/"*.yml | sha256sum; }

# --- check-workflow-pins.sh ---------------------------------------------------------------
fresh_copy
pins=$t/r/scripts/check-workflow-pins.sh
check "pins: the unreleased placeholder passes with --allow-unreleased" "$pins" --allow-unreleased
fails_saying() { ! "$@" >"$t/o" 2>&1 && grep -q -- "$want" "$t/o"; }
want=all-zero
check "pins: the unreleased placeholder fails without the flag" fails_saying "$pins"
sed -i -E "0,/RSOLV_HOST_SHA256_X64: /s/(RSOLV_HOST_SHA256_X64: )\"0/\1\"1/" "$t/r/.github/workflows/rsolv-work.yml"
want=RSOLV_HOST_SHA256_X64
check "pins: one changed hash fails, naming the key" fails_saying "$pins" --allow-unreleased
fresh_copy
sed -i 's/--retry 3/--retry 4/' "$t/r/.github/workflows/rsolv-publish.yml"
want="install-host"
check "pins: a changed install-host block fails" fails_saying "$pins" --allow-unreleased

# --- pin-host.sh, against a fake gh ---------------------------------------------------------
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
  "attestation verify") exit "$(cat "$f/attest_rc")" ;;
  "api "*/commits/*) echo 1111111111111111111111111111111111111111 ;;
  "api "*/compare/*) cat "$f/compare" ;;
  *) echo "fake gh: unexpected $*" >&2; exit 64 ;;
esac
EOF
chmod +x "$t/bin/gh"
printf 'x64 binary\n' >"$t/fake/assets/rsolv-host-linux-x86_64"
printf 'arm binary\n' >"$t/fake/assets/rsolv-host-linux-aarch64"
(cd "$t/fake/assets" && sha256sum rsolv-host-linux-x86_64 rsolv-host-linux-aarch64 >SHA256SUMS)
x64_sum=$(awk '$2 == "rsolv-host-linux-x86_64" {print $1}' "$t/fake/assets/SHA256SUMS")
arm_sum=$(awk '$2 == "rsolv-host-linux-aarch64" {print $1}' "$t/fake/assets/SHA256SUMS")

fake_gh() { # version released attest_rc release_rc compare
  echo "$1" >"$t/fake/version"
  if [ "$2" = yes ]; then touch "$t/fake/released"; else rm -f "$t/fake/released"; fi
  echo "$3" >"$t/fake/attest_rc"
  echo "$4" >"$t/fake/release_rc"
  echo "$5" >"$t/fake/compare"
  : >"$t/fake/log"
}
pin() { PATH="$t/bin:$PATH" FAKE_GH="$t/fake" "$t/r/scripts/pin-host.sh" "$@" >"$t/pin.out" 2>&1; }
refuses_unchanged() { # name, then pin-host args
  local name=$1 before
  shift
  fresh_copy
  before=$(workflows_sum)
  check "pin-host: $name is refused" bash -c '! pin "$@"' _ "$@"
  check "pin-host: $name changes no workflow" test "$before" = "$(workflows_sum)"
}
export -f pin
export t

fake_gh 2.102.0 yes 0 0 ahead
refuses_unchanged "a malformed version" 0.1
fake_gh 2.101.9 yes 0 0 ahead
refuses_unchanged "a gh older than 2.102.0" 0.1.0
fake_gh 2.102.0 no 0 0 ahead
refuses_unchanged "a missing release" 0.0.0
fake_gh 2.102.0 yes 1 0 ahead
refuses_unchanged "a failed attestation (a PR dry run's, say)" 0.1.0
fake_gh 2.102.0 yes 0 1 ahead
refuses_unchanged "a failed release verification" 0.1.0
fake_gh 2.102.0 yes 0 0 diverged
refuses_unchanged "a tag commit off main" 0.1.0
fake_gh 2.102.0 yes 0 0 ahead
printf 'tampered\n' >>"$t/fake/assets/rsolv-host-linux-aarch64"
refuses_unchanged "an asset that doesn't match SHA256SUMS" 0.1.0
printf 'arm binary\n' >"$t/fake/assets/rsolv-host-linux-aarch64"

fake_gh 2.102.0 yes 0 0 ahead
fresh_copy
check "pin-host: a verified release is pinned" pin 0.1.0
wf=$t/r/.github/workflows
check "pin-host: the x64 SHA-256 is written to all three role workflows" \
  test "$(cat "$wf"/rsolv-{scan,work,publish}.yml | grep -c "RSOLV_HOST_SHA256_X64: \"$x64_sum\"")" -eq 3
check "pin-host: the arm64 SHA-256 is written to all three role workflows" \
  test "$(cat "$wf"/rsolv-{scan,work,publish}.yml | grep -c "RSOLV_HOST_SHA256_ARM64: \"$arm_sum\"")" -eq 3
check "pin-host: the version is written" \
  test "$(cat "$wf"/rsolv-{scan,work,publish}.yml | grep -c 'RSOLV_HOST_VERSION: "0.1.0"')" -eq 3
check "pin-host: the pinned workflows pass the strict pin check" "$t/r/scripts/check-workflow-pins.sh"
check "pin-host: the tag commit is resolved through refs/tags/" \
  grep -q 'gh api repos/RSOLV-dev/rsolv-host/commits/refs/tags/host-v0.1.0 --jq .sha' "$t/fake/log"
want="--repo RSOLV-dev/rsolv-host --signer-workflow RSOLV-dev/rsolv-host/.github/workflows/host-release.yml"
want="$want --source-ref refs/tags/host-v0.1.0 --source-digest 1111111111111111111111111111111111111111 --deny-self-hosted-runners"
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
rcs=$(cat "$RUNNER_TEMP/rcs" 2>/dev/null)
rc=${rcs%% *}
echo "${rcs#"$rc"}" | sed 's/^ //' >"$RUNNER_TEMP/rcs"
[ "${rc:-0}" -eq 0 ] && echo "outcome=mitigated" >>"$GITHUB_OUTPUT"
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
    ISSUE=7 MAX_ISSUES=5 RSOLV_DECISION_KEYS="[]" EXACT_RUNTIME_VERSIONS=false "$@" \
    bash -e "$rt/step.sh" >"$rt/stdout" 2>&1 || rc=$?
}
calls() { grep -c '^ARGS' "$rt/calls" 2>/dev/null || echo 0; }
nth_args() { grep '^ARGS' "$rt/calls" | sed -n "${1}p"; }
env_of() { awk -v n="$1" '/^ARGS/ {i++} i == n && /^ENV / {print $2}' "$rt/calls" | sort | tr '\n' ' '; }
: >"$t/stub/curl.log"

for spec in rsolv-scan.yml:scan rsolv-work.yml:work rsolv-publish.yml:publish; do
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
for spec in rsolv-scan.yml:scan rsolv-work.yml:work rsolv-publish.yml:publish; do
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

[ "$fails" -eq 0 ] || { echo "$fails test(s) failed"; exit 1; }
echo "all passed"
