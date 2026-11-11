# v5 release runbook (RFC-150)

Three things leave this repository for v5: the sandbox image, the reusable workflows' commit SHAs (which the platform allowlists), and the customer template that calls them. Each has a check that must pass before anyone pins or allowlists it.

## Releasing the sandbox image

`.github/workflows/sandbox-image.yml` builds `ghcr.io/rsolv-dev/rsolv-sandbox`.

- **On a pull request** it builds the `sandbox` target natively for amd64 and arm64, smoke-tests each image from the exported archive, and checks the archives against the digests the build recorded. It pushes nothing, and its jobs hold only `contents: read`.
- **On a `sandbox-vX.Y.Z` tag** the `publish` job also runs, behind the `release` environment, which needs the owner's approval. It:
  1. refuses a tag whose commit isn't a first-parent commit of `main`;
  2. re-verifies the tested archives and pushes them unchanged (`skopeo copy --preserve-digests`);
  3. creates the multi-architecture index under the tag;
  4. attests the index digest with `actions/attest-build-provenance` (`push-to-registry: true`).

  Only this job holds `packages: write`, `id-token: write` and `attestations: write`.

Only admins can create `sandbox-v*` tags, and nobody can move or delete one (repository tag rulesets). The tag is pushed from `main` after the change has merged. A tag runs the workflow file at the tagged commit, so it's the repository settings, not this file, that stop an unmerged commit from publishing.

## Pinning the sandbox image in rsolv-host

`rsolv-host` pins the index digest in `rsolv_host/config/config.exs` (`sandbox_image`). A digest gets pinned only after this passes, with `gh` 2.102.0 or later (older versions can pass attestations these flags are meant to reject):

```sh
gh attestation verify oci://ghcr.io/rsolv-dev/rsolv-sandbox@<digest> --repo RSOLV-dev/RSOLV-action \
  --signer-workflow RSOLV-dev/RSOLV-action/.github/workflows/sandbox-image.yml \
  --source-ref refs/tags/sandbox-v<x> --source-digest <tag commit> --deny-self-hosted-runners
```

- `--source-ref` and `--source-digest` bind the image to the release tag and its commit. A pull request run never attests, and an attestation from any other ref or commit fails.
- `--signer-workflow` binds it to this workflow. `--deny-self-hosted-runners` rejects a build on a runner we don't control.

`scripts/pin-sandbox.sh <version> <sha256:digest> <rsolv-host checkout>` does all of it, and writes nothing until every check has passed:
1. checks that `gh` is 2.102.0 or later;
2. resolves the tag's commit through `refs/tags/`;
3. checks that commit is a first-parent commit of `main` (`scripts/check-first-parent.sh`);
4. runs the verification above;
5. writes the pin.

Commit the change to `rsolv-host` through a pull request. The digest is the one in the `publish` job's summary.

## Allowlisting a workflow commit

Before a commit SHA goes into the platform's `RSOLV_RUNNER_WORKFLOW_SHAS`, confirm it's a first-parent commit of `main`:

```sh
scripts/check-first-parent.sh <40-hex SHA>
```

GitHub serves any commit in the fork network under `RSOLV-dev/rsolv-action/...@<sha>`, including one pushed only to a fork (an "impostor" commit). A commit from inside a merged branch was never reviewed as `main`. Neither may be allowlisted.

## The customer template's pins

`TEMPLATE-rsolv-v5.yml` calls the reusable workflows by a full commit SHA. `scripts/check-workflow-pins.sh` always checks that both calls use one 40-hex commit. Until the first v5 release, that commit is the all-zero placeholder. From the first release, CI runs it with `--strict`, which refuses the placeholder.
