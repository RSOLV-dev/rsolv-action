#!/usr/bin/env bash
# Succeeds only if <sha> is a first-parent commit of RSOLV-action's main: a commit main itself
# passed through, not one from inside a merged branch, and not a fork-network ("impostor") commit,
# which GitHub also serves under RSOLV-dev/rsolv-action. Run it before a workflow commit goes into
# the platform's RSOLV_RUNNER_WORKFLOW_SHAS (docs/V5-RELEASE.md); pin-sandbox.sh runs it on the tag.
#   check-first-parent.sh <40-hex commit SHA>   (RSOLV_ACTION_REMOTE overrides the remote: for
#   tests, and pin-host.sh's check of RSOLV-dev/rsolv-host)
set -euo pipefail
sha=${1:-}
[[ $sha =~ ^[0-9a-f]{40}$ ]] || { echo "usage: check-first-parent.sh <40-hex commit SHA>" >&2; exit 2; }
remote=${RSOLV_ACTION_REMOTE:-https://github.com/RSOLV-dev/RSOLV-action.git}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
git clone -q --bare --filter=blob:none --single-branch --branch main "$remote" "$work/r"
# Not grep -q: it exits at the match and, under pipefail, git's SIGPIPE fails the check.
git -C "$work/r" rev-list --first-parent main | grep -xF "$sha" >/dev/null ||
  { echo "::error::$sha is not a first-parent commit of $remote main" >&2; exit 1; }
echo "$sha is a first-parent commit of main"
