---
name: rfc7523
description: "RFC 7523: JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants. Profiles the OAuth Assertion Framework (RFC 7521) to define (1) the jwt-bearer authorization grant for requesting an access token from an existing trust relationship without a user-approval step, and (2) JWT-based client authentication at the token endpoint via client_assertion. The basis for the private_key_jwt client authentication method. Use when implementing or validating signed JWT assertions for OAuth token requests, client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer, or iss/sub/aud/exp claim validation."
---

# RFC 7523: JWT Profile for OAuth 2.0 Client Authentication and Authorization Grants

**Category:** Standards Track
**Published:** May 2015
**Authors:** M. Jones (Microsoft), B. Campbell (Ping Identity), C. Mortimore (Salesforce)
**Profiles:** RFC 7521 (OAuth Assertion Framework)
**Related to:** RFC 6749 (OAuth 2.0), RFC 7519 (JWT), RFC 7522 (SAML 2.0 Profile)

This specification profiles the abstract **OAuth Assertion Framework** (RFC 7521) for **JSON Web Tokens**, defining two orthogonal and separable uses of a signed JWT in an OAuth 2.0 access-token request:

1. **JWT as an authorization grant** — request an access token using an existing trust relationship expressed by the JWT, without a direct user-approval step.
2. **JWT for client authentication** — authenticate the client to the token endpoint as an alternative to a shared `client_secret`.

These two uses can be combined or used separately. Client authentication via JWT is "nothing more than an alternative way for a client to authenticate to the token endpoint" and must accompany some grant type to form a complete request.

> **Why this skill matters for reauth:** the `private_key_jwt` client authentication method (OpenID Connect Core `token_endpoint_auth_method`) is RFC 7523 §2.2 client authentication, with the assertion signed asymmetrically. This RFC is the authoritative source for the `client_assertion` / `client_assertion_type` parameters and the JWT claim-validation rules that an authorization server enforces.

## When to Use This Skill

Use this skill when working with:
- `private_key_jwt` client authentication (OIDC) and its claim construction/validation
- The `client_assertion` and `client_assertion_type` token-endpoint parameters
- The `urn:ietf:params:oauth:grant-type:jwt-bearer` authorization grant
- Building or validating signed JWT assertions for OAuth token requests
- `iss` / `sub` / `aud` / `exp` / `nbf` / `iat` / `jti` claim semantics for assertions
- Replay protection (`jti`) for OAuth assertions
- Distinguishing JWT-as-grant from JWT-as-client-authentication

## Two Independent Mechanisms

| | Authorization Grant (§2.1) | Client Authentication (§2.2) |
|---|---|---|
| **Purpose** | Obtain an access token from a trust relationship | Authenticate the client at the token endpoint |
| **Parameter carrying the JWT** | `assertion` | `client_assertion` |
| **Selecting parameter** | `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` | `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` |
| **`sub` claim** | The authorized accessor (resource owner / delegate; may be pseudonymous) | MUST be the `client_id` of the OAuth client |
| **Error on invalid JWT** | `invalid_grant` | `invalid_client` |
| **Combined with a grant?** | It *is* the grant | Yes — accompanies another `grant_type` (e.g. `authorization_code`, `client_credentials`) |

## §2.1 — Using a JWT as an Authorization Grant

```
POST /token.oauth2 HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer
&assertion=eyJhbGciOiJFUzI1NiIsImtpZCI6IjE2In0.eyJpc3Mi...[JWT]
```

- `grant_type` MUST be `urn:ietf:params:oauth:grant-type:jwt-bearer`.
- `assertion` MUST contain a **single** JWT.
- `scope` MAY be used to request scope.
- Client authentication is **optional** here; `client_id` is only needed when a client-authentication method that relies on it is used.

## §2.2 — Using a JWT for Client Authentication (the `private_key_jwt` path)

```
POST /token.oauth2 HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=n0esc3NRze7LTCu7iYzS6a5acc3f0ogp4
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
&client_assertion=eyJhbGciOiJSUzI1NiIsImtpZCI6IjIyIn0.eyJpc3Mi...[JWT]
```

- `client_assertion_type` MUST be `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`.
- `client_assertion` contains a **single** JWT; it MUST NOT contain more than one.
- The assertion accompanies a normal grant request (`authorization_code`, `client_credentials`, etc.).
- For `private_key_jwt`, the JWT is signed with the client's private key; the AS verifies with the client's registered public key (e.g. via `jwks` / `jwks_uri`).

## §3 — JWT Format and Processing Requirements (AS validation)

The authorization server **MUST** validate the JWT against all of the following:

| # | Claim | Requirement |
|---|-------|-------------|
| 1 | `iss` | **MUST** be present; unique identifier of the issuer. Compare with **Simple String Comparison** (RFC 3986 §6.2.1) absent a profile saying otherwise. |
| 2 | `sub` | **MUST** be present. For a grant: the authorized accessor (may be pseudonymous). For **client authentication: MUST be the `client_id`**. |
| 3 | `aud` | **MUST** be present and identify the AS. The token-endpoint URL MAY be used. AS **MUST reject** any JWT that does not list its own identity as audience. Simple String Comparison. |
| 4 | `exp` | **MUST** be present. AS **MUST reject** expired JWTs (subject to allowable clock skew). MAY reject `exp` unreasonably far in the future. |
| 5 | `nbf` | MAY be present; if so, token MUST NOT be accepted before this time. |
| 6 | `iat` | MAY be present. AS MAY reject `iat` unreasonably far in the past. |
| 7 | `jti` | MAY be present. AS **MAY enforce replay protection** by tracking used `jti` values for the JWT's validity window. |
| 8 | other | The JWT MAY contain other claims. |
| 9 | signature | The JWT **MUST** be digitally signed or MAC'd by the issuer. AS **MUST reject** invalid signatures/MACs. |
| 10 | JWT validity | AS **MUST reject** a JWT invalid in any other respect per RFC 7519 (JWT). |

### Error responses

| Context | `error` code |
|---------|--------------|
| Invalid JWT used as **authorization grant** (§3.1) | `invalid_grant` |
| Invalid JWT used for **client authentication** (§3.2) | `invalid_client` |

```
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store

{ "error": "invalid_grant", "error_description": "Audience validation failed" }
```

If client credentials are present alongside a JWT grant, the AS MUST validate them.

## §4 — Example JWT Claims Set

```json
{
  "iss": "https://jwt-idp.example.com",
  "sub": "mailto:mike@example.com",
  "aud": "https://jwt-rp.example.net",
  "nbf": 1300815780,
  "exp": 1300819380,
  "http://claims.example.com/member": true
}
```

Header (ECDSA P-256 / SHA-256, key id `16`):

```json
{ "alg": "ES256", "kid": "16" }
```

## §6 — Security Considerations

- All security considerations of RFC 7521, RFC 6749, and RFC 7519 (JWT) apply.
- **Replay protection is NOT mandated** for either use — it is an optional feature (see `jti`, claim 7) that implementations MAY employ at their discretion.

## §7 — Privacy Considerations

- A JWT may carry privacy-sensitive data; transmit only over encrypted channels (TLS), or encrypt the JWT to the AS.
- Include only the minimum claims necessary; `sub` MAY be an anonymous/pseudonymous value.

## §8 — IANA Registrations (OAuth URI registry)

| URN | Use |
|-----|-----|
| `urn:ietf:params:oauth:grant-type:jwt-bearer` | JWT Bearer authorization grant type |
| `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` | JWT Bearer client authentication assertion type |

## Quick Reference

| Section | Title |
|---------|-------|
| 1 | Introduction |
| 1.2 | Terminology |
| 2 | HTTP Parameter Bindings for Transporting Assertions |
| 2.1 | Using JWTs as Authorization Grants |
| 2.2 | Using JWTs for Client Authentication |
| 3 | JWT Format and Processing Requirements |
| 3.1 | Authorization Grant Processing |
| 3.2 | Client Authentication Processing |
| 4 | Authorization Grant Example |
| 5 | Interoperability Considerations |
| 6 | Security Considerations |
| 7 | Privacy Considerations |
| 8 | IANA Considerations |

## Implementation Checklist (client authentication / `private_key_jwt`)

- [ ] Set `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
- [ ] Send exactly one JWT in `client_assertion`
- [ ] Set `iss` = `sub` = `client_id`
- [ ] Set `aud` to the AS token endpoint (or AS-published identifier)
- [ ] Include a short-lived `exp` (and consider `nbf` / `iat`)
- [ ] Include a unique `jti` if the AS enforces replay protection
- [ ] Sign the JWT (asymmetric key for `private_key_jwt`); ensure the AS can resolve the verification key (`kid` / `jwks`)
- [ ] On the AS side, reject on bad `aud`, expired `exp`, bad signature → `invalid_client`

## Related RFCs

- **RFC 7521**: Assertion Framework for OAuth 2.0 (the abstract framework this profiles)
- **RFC 6749**: The OAuth 2.0 Authorization Framework
- **RFC 7519**: JSON Web Token (JWT)
- **RFC 7522**: SAML 2.0 Profile for OAuth 2.0 (sibling profile)
- **RFC 6755**: An IETF URN Sub-Namespace for OAuth
- **OpenID Connect Core**: defines `private_key_jwt` / `client_secret_jwt` `token_endpoint_auth_method` values built on this profile

## Full RFC Text

See [references/RFC7523.txt](references/RFC7523.txt) for the complete document.
