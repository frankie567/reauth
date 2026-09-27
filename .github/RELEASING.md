# Preparing a release

1. Write user-facing notes under `Unreleased` in `CHANGELOG.md`, using Added,
   Changed, Deprecated, Removed, Fixed, or Security categories as needed.
   Include migration instructions for breaking changes. Coordinate disclosure
   before committing details of a private vulnerability.
2. Run `just changelog <version>` (for example, `just changelog 0.5.0`).
   keepachangelog creates a dated section and updates comparison links.
   Preview it with `just release-notes <version>`, then review and merge it.
   These commands do not commit, tag, or publish anything.
3. Run `just lint`, `just test`, `just docs-build`, and `just build`.
4. From the clean, reviewed checkout, run `just version <version>` with the same
   explicit version. The existing Hatch plugin updates the package version,
   opens the commit editor, and creates a signed `v<version>` tag. Review before
   pushing the commit and tag using the repository's authorized release process.
   Do not reuse or move release tags.
5. CI checks the tag against the package version and extracts that version's
   changelog entry. Missing or empty notes fail before publication. The entry
   becomes the draft GitHub release body and a versioned, attested attachment.
   CI never rewrites `CHANGELOG.md` after a release.
6. Verify the assets and review the draft before publishing the GitHub release.
   PyPI publication already occurs in CI; the GitHub draft is not a staging gate
   for PyPI. See [CI security](CI_SECURITY.md) for gates and verification commands.
