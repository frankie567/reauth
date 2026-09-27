# Changelog

Add curated entries under `Unreleased`, using [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
categories. Run `just changelog <version>` before tagging to create a dated entry.
Public security details must follow coordinated disclosure.
See [release instructions](.github/RELEASING.md). Earlier release notes are in [GitHub Releases](https://github.com/frankie567/reauth/releases).

## [Unreleased]

### Changed

- Manage curated changelog entries with keepachangelog and use each version's entry for GitHub release notes.

## [0.4.2] - 2026-09-26

### Fixed

- Handle non-ASCII inputs in TOTP and HOTP gracefully.

Source: [v0.4.2 release notes](https://github.com/frankie567/reauth/releases/tag/v0.4.2).

[Unreleased]: https://github.com/frankie567/reauth/compare/v0.4.2...HEAD
[0.4.2]: https://github.com/frankie567/reauth/releases/tag/v0.4.2
