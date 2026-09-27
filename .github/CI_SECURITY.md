# CI security

The main ruleset requires `tests-passed`, `security-analysis / Analyze (python)`,
and `dependency-review` separately. The administrator bypass remains configured.
`tests-passed` aggregates only the test job; release publishing also requires
CodeQL. Dependency Review rejects newly introduced known vulnerabilities at any
severity. CodeQL rejects unsuppressed findings from the configured Python suite.
Fix findings before merging or releasing; suppress only with a reviewed,
specific explanation and supporting evidence that the finding is not exploitable.

Builds install locked runtime and build dependencies. A read-only job validates
the release tag against the package version, builds distributions, and uploads
assets and SHA-256 hashes. The publishing job downloads those same assets,
attests them, publishes through PyPI trusted publishing, and creates a draft
GitHub release. It does not check out or build project code with release permissions.
PyPI publication occurs before review of the GitHub draft.

Workflow defaults are read-only. Write permissions are scoped to deployment,
security reporting, and publishing jobs. The build checkout does not retain Git credentials.

## Verify release assets

Download the assets with `gh release download v<VERSION> --repo frankie567/reauth`.
Verify each wheel, source archive, and `SHA256SUMS` against the expected tag and
reviewed commit:

```sh
gh attestation verify ASSET --repo frankie567/reauth \
  --signer-workflow frankie567/reauth/.github/workflows/build.yml \
  --cert-oidc-issuer https://token.actions.githubusercontent.com \
  --source-ref refs/tags/v<VERSION> --source-digest <COMMIT_SHA> \
  --deny-self-hosted-runners
```

Replace all placeholders. A missing or invalid attestation is a failure.
After verifying `SHA256SUMS`, run `sha256sum --check SHA256SUMS` (macOS:
`shasum -a 256 --check SHA256SUMS`). Attestations establish provenance, not the
absence of vulnerabilities. Releases through v0.4.2 predate this workflow.

Branch rules do not protect release tags. Restrict tag creation and the release
environment separately. Dependency Review covers pull-request changes; this
workflow does not add full-dependency scanning on release tags.
