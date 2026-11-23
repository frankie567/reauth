# Changelog

Add curated entries under `Unreleased`, using [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
categories. From a clean checkout, run `just version patch` (or `minor`, `major`,
or an explicit version) to update the package version and changelog, open the
commit editor, and create a signed commit. After the release PR merges into `main`,
run `just release <PR number>` to sign and push the release tag.
Use `just release-notes <version>` to preview the GitHub release body.
Public security details must follow coordinated disclosure.
Earlier release notes are in [GitHub Releases](https://github.com/frankie567/reauth/releases).

## [Unreleased]

### Added

- WebAuthn factor with multiple credentials per identity, attestation policy, single-use ceremony state, and SQLAlchemy storage.
- Password factor with enrollment, verification, password changes, and single-use reset tokens. The `password` extra provides Argon2 hashing through pwdlib.
- SQLAlchemy adapters and table factories for authentication and identity sessions, backup codes, email OTP, HOTP, TOTP, and OAuth2 enrollments and state. `SQLAlchemyPasswordFactor` stores password state in the application's identity table.

### Changed

- `FactorBase` now uses `get_enrollments()` to support multiple enrollments per identity. Custom factors with a singular `get_enrollment()` can inherit from `SingleEnrollmentFactorBase`.
- Replace `reauth.crypto` with injectable token providers and verifiers in `reauth.tokens`, including checksummed tokens and an HMAC verifier with key rotation. Update custom persistence to store token identifiers and verifiers for sessions and OAuth2 state, and code verifiers for email OTP and backup codes.
- `AuthenticationSessionService.advance()` and `complete()` now take the session token and validate it before changing the session.
- `OAuth2Factor.callback()` now requires `expected_state`. Save the state returned by `start()` in the initiating browser's flow and pass the saved value to the callback.
- Callers own transaction commits and rollbacks for identity session storage. Commit any session-family revocation triggered by `ReusedRefreshTokenException` before handling the failure outside the transaction.

### Fixed

- Raise `InvalidIDTokenException` for malformed OpenID Connect ID tokens.

## [0.5.0] - 2026-10-27

### Changed

- GitHub OAuth2's `get_primary_email()` now returns the primary email address and its verification status as a tuple.

### Fixed

- Keep TOTP verification within the configured clock drift window.

Source: [v0.5.0 release notes](https://github.com/frankie567/reauth/releases/tag/v0.5.0).

## [0.4.2] - 2026-09-26

### Fixed

- Handle non-ASCII inputs in TOTP and HOTP gracefully.

Source: [v0.4.2 release notes](https://github.com/frankie567/reauth/releases/tag/v0.4.2).

[Unreleased]: https://github.com/frankie567/reauth/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/frankie567/reauth/releases/tag/v0.5.0
[0.4.2]: https://github.com/frankie567/reauth/releases/tag/v0.4.2
