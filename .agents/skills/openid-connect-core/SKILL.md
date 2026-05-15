---
name: openid-connect-core
description: "OpenID Connect Core 1.0 - Identity layer on top of OAuth 2.0 protocol. Defines ID Token, UserInfo endpoint, authentication flows (Authorization Code, Implicit, Hybrid), claims, and standard claims for identity. Use when working with OpenID Connect authentication, identity tokens, user profile information, or OAuth 2.0 extensions for identity."
---

# OpenID Connect Core 1.0

OpenID Connect 1.0 is a simple identity layer on top of the OAuth 2.0 protocol. It enables Clients (Relying Parties) to verify the identity of the End-User based on the authentication performed by an Authorization Server (OpenID Provider), as well as to obtain basic profile information about the End-User in an interoperable and REST-like manner.

This specification defines core OpenID Connect functionality: authentication built on top of OAuth 2.0 and the use of Claims to communicate information about the End-User.

## When to Use This Skill

Use this skill when working with:
- OpenID Connect authentication flows and identity verification
- ID Token creation, validation, and usage
- UserInfo endpoint implementation and claims retrieval
- Standard claims (sub, name, email, picture, etc.)
- Authorization Code, Implicit, and Hybrid flows for authentication
- Self-Issued OpenID Providers
- Subject identifiers and pairwise pseudonymous identifiers
- Request Objects and Request URIs
- Signatures and encryption for identity tokens
- Security considerations for identity protocols

## Key Concepts

### Core Entities
- **Relying Party (RP)**: OAuth 2.0 Client application requiring End-User Authentication and Claims from an OpenID Provider
- **OpenID Provider (OP)**: OAuth 2.0 Authorization Server capable of Authenticating the End-User and providing Claims
- **End-User**: Human participant whose Authentication is desired

### Core Components
- **ID Token**: JWT containing Claims about the Authentication event and the End-User
- **UserInfo Endpoint**: Protected resource returning authorized information about the End-User
- **Claims**: Assertions about the End-User (standard claims include: sub, name, family_name, given_name, middle_name, nickname, preferred_username, profile, picture, website, email, email_verified, gender, birthdate, zoneinfo, locale, phone_number, phone_number_verified, address, updated_at)

### Authentication Flows
- **Authorization Code Flow**: Most common flow using authorization code exchange
- **Implicit Flow**: Legacy flow returning tokens directly in URL fragment
- **Hybrid Flow**: Combines elements of both Authorization Code and Implicit flows

### Security Features
- Request Objects and Request URIs for passing parameters as JWTs
- Self-Issued OpenID Provider support
- Subject Identifier types including Pairwise Pseudonymous Identifier (PPID)
- Signing and encryption for tokens
- Security considerations for token handling and transmission

## Specification Sections

1. **ID Token** - Structure and validation of identity tokens
2. **Authentication** - Authorization Code, Implicit, and Hybrid flows
3. **Claims** - Standard claims, UserInfo endpoint, claim types
4. **Request Objects** - Passing request parameters as JWTs
5. **Self-Issued OpenID Provider** - Personal self-hosted providers
6. **Signatures and Encryption** - Cryptographic protection
7. **Security Considerations** - Comprehensive security guidance

## Full Specification Text

See [references/openid-connect-core-1_0.txt](references/openid-connect-core-1_0.txt) for the complete OpenID Connect Core 1.0 specification.
