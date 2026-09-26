---
hide:
    - navigation
---

# Getting started

Reauth is an authentication toolkit for Python 3.14 and later.

## Installation

Add Reauth to your project with [uv](https://docs.astral.sh/uv/) or pip:

=== "uv"

    ```bash
    uv add reauth
    ```

=== "pip"

    ```bash
    pip install reauth
    ```

## Explore the toolkit

Reauth provides authentication building blocks that you integrate with your
application and data storage:

- **Factors**: email OTP, HOTP, TOTP, backup codes, and OAuth 2.0 / OpenID Connect login.
- **Authentication sessions**: coordinate multi-factor authentication workflows.
- **Identity sessions**: manage sessions after authentication.

Browse the [API reference](reference/index.md) for module documentation. Integration
guides are still to come; explore the
[source code](https://github.com/frankie567/reauth/tree/main/reauth) and
[tests](https://github.com/frankie567/reauth/tree/main/tests) for usage examples.

!!! warning "Expect API changes"

    Reauth is an early-stage project. Pin your dependency version and review changes
    before upgrading.
