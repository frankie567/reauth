# Reauth

<p align="center">
    <em>The authentication toolkit for Python</em>
</p>

[![build](https://github.com/frankie567/reauth/workflows/Build/badge.svg)](https://github.com/frankie567/reauth/actions)
[![codecov](https://codecov.io/gh/frankie567/reauth/branch/master/graph/badge.svg)](https://codecov.io/gh/frankie567/reauth)
[![PyPI version](https://badge.fury.io/py/reauth.svg)](https://badge.fury.io/py/reauth)

---

**Documentation**: <a href="https://frankie567.github.io/reauth/" target="_blank">https://frankie567.github.io/reauth/</a>

**Source Code**: <a href="https://github.com/frankie567/reauth" target="_blank">https://github.com/frankie567/reauth</a>

---

> [!WARNING]
> This is an early-stage project with many moving parts and mostly missing documentation. The API is not yet stable and breaking changes are expected.

## Roadmap

Our vision is to build a comprehensive, flexible authentication toolkit for Python that handles everything from low-level factor primitives to high-level OIDC server capabilities.

### Short-term: Core Foundation

- [ ] Factor primitives — building blocks for authentication factors
    - [x] Email OTP
    - [x] HOTP
    - [x] TOTP
    - [ ] Passwords
    - [ ] Security keys
    - [ ] Passkeys
    - [ ] Social Login
- [x] MFA authentication management — multi-factor authentication workflows

### Mid-term: Integration Layer

- [ ] Sessions management — robust session handling
- [ ] ORM and web frameworks wrappers — seamless integration with popular frameworks

### Long-term: Full Platform

- [ ] OIDC server — complete OpenID Connect provider implementation
- [ ] Team management — multi-user and organizational features
- [ ] And more — expanding the ecosystem

## Development

### Setup environment

We use [uv](https://docs.astral.sh/uv/) to manage the development environment and production build, and [just](https://github.com/casey/just) to manage command shortcuts. Ensure they are installed on your system.

### Run unit tests

You can run all the tests with:

```bash
just test
```

### Format the code

Execute the following command to apply linting and check typing:

```bash
just lint
```

### Publish a new version

You can bump the version, create a commit and associated tag with one command:

```bash
just version patch
```

```bash
just version minor
```

```bash
just version major
```

Your default Git text editor will open so you can add information about the release.

When you push the tag on GitHub, the workflow will automatically publish it on PyPi and a GitHub release will be created as draft.

## Serve the documentation

You can serve the Mkdocs documentation with:

```bash
just docs-serve
```

It'll automatically watch for changes in your code.

## License

This project is licensed under the terms of the MIT license.
