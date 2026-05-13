---
name: rfc7636
description: "RFC 7636: Proof Key for Code Exchange by OAuth Public Clients. Defines PKCE extension for OAuth 2.0 Authorization Code flow, mitigating authorization code interception attacks by introducing code_verifier and code_challenge parameters. Enables secure OAuth usage for public clients like mobile apps and SPAs."
---

# RFC 7636: Proof Key for Code Exchange by OAuth Public Clients

**Category:** Standards Track
**Published:** September 2015
**Authors:** N. Sakimura (Editor), J. Bradley, N. Agarwal
**Related to:** RFC 6749 (OAuth 2.0)

This specification addresses the **authorization code interception attack** against OAuth 2.0 public clients (mobile apps, single-page applications) by introducing **Proof Key for Code Exchange (PKCE, pronounced "pixy")**.

PKCE adds cryptographic proof-of-possession to the Authorization Code flow, ensuring that the client that initiated the authorization request is the same client that redeems the authorization code for tokens.

## When to Use This Skill

Use this skill when working with:
- PKCE implementation for OAuth 2.0 public clients
- Mobile application authentication flows
- Single-page application (SPA) authentication
- Authorization code interception attack mitigation
- OAuth 2.0 security extensions
- code_verifier and code_challenge generation
- S256 and plain code challenge methods

## Problem Addressed: Authorization Code Interception Attack

OAuth 2.0 public clients are susceptible to authorization code interception attacks:

1. Malicious app registers the same custom URI scheme as the legitimate OAuth client
2. Operating system routes the authorization code response to the malicious app
3. Attacker exchanges the intercepted code for an access token
4. Attacker gains unauthorized access to protected resources

PKCE mitigates this by requiring the client to prove possession of a secret (code_verifier) that is never sent through the browser/OS.

## Attack Flow Diagram

```
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+
| End Device (e.g., Smartphone)  |
|                                |
| +-------------+   +----------+ | (6) Access Token  +----------+
| |Legitimate   |   | Malicious|<--------------------|          |
| |OAuth 2.0 App|   | App      |-------------------->|          |
| +-------------+   +----------+ | (5) Authorization |          |
|        |    ^          ^       |        Grant      |  Authz   |
|        |     \         |       |                   |  Server  |
|        |      \   (4)  |       |                   |          |
|    (1) |       \  Authz|       |                   |          |
|   Authz|        \ Code |       |                   |          |
| Request|         \     |       |                   |          |
|        |          \    |       |                   |          |
|        |           \   |       |                   +----------+
| +----------------------------+ | 
| |     Operating System/      |<----(3)-----------|
| |         Browser            |-----(2)--------->|          |
| +----------------------------+ |                   +----------+
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+
```

## Protocol Flow with PKCE

```
+--------+                                +-------------------+
|        |                                |   Authz Server    |
|        |--(A)- Authorization Request ---->| +---------------+ |
|        |       + code_challenge, t_m       | | Authorization | |
|        |                                | |    Endpoint   | |
|        |<-(B)---- Authorization Code -----| +---------------+ |
| Client |                                |                   |
|        |                                | +---------------+ |
|        |--(C)-- Access Token Request ---->| |    Token      | |
|        |          + code_verifier         | |   Endpoint    | |
|        |                                | +---------------+ |
|        |<-(D)------ Access Token ---------|                   |
+--------+                                +-------------------+
```

**Steps:**
1. **(A)** Client sends authorization request with code_challenge and code_challenge_method
2. **(B)** Authorization server returns authorization code, stores code_challenge + method association
3. **(C)** Client sends access token request with authorization code AND code_verifier
4. **(D)** Server verifies code_verifier against stored code_challenge, issues tokens if valid

## Protocol Details

### 4.1 Client Creates a Code Verifier

The client generates a high-entropy cryptographic random string:

- **Characters:** unreserved URI characters `[A-Z]`, `[a-z]`, `[0-9]`, `-`, `.`, `_`, `~`
- **Length:** Minimum 43 characters, maximum 128 characters
- **Entropy:** RECOMMENDED minimum 256 bits (32-octet random sequence base64url-encoded)

```
code_verifier = high-entropy cryptographic random STRING
```

**Best Practice:** Use a cryptographically secure random number generator to create a 32-octet sequence, then base64url-encode to produce a 43-octet URL-safe string.

### 4.2 Client Creates the Code Challenge

The client transforms the code_verifier into a code_challenge using one method:

#### S256 (Mandatory to Implement)
```
code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
```

#### Plain (Legacy)
```
code_challenge = code_verifier
```

**Rule:** Clients capable of using "S256" MUST use "S256". The "plain" method is for compatibility only and SHOULD NOT be used in new implementations.

### 4.3 Client Sends Code Challenge with Authorization Request

Additional parameters sent to Authorization Endpoint (Section 4.1.1 of RFC 6749):

| Parameter | Required | Description |
|-----------|----------|-------------|
| `code_challenge` | YES | The transformed code verifier |
| `code_challenge_method` | NO (default: "plain") | Transformation method: "S256" or "plain" |

### 4.4 Server Returns the Code

The authorization server:
- Issues the authorization code as usual
- MUST associate the code_challenge and code_challenge_method with the authorization code
- Stores them encrypted in the code or on the server
- MUST NOT expose code_challenge in a form that other entities can extract

### 4.5 Client Sends Authorization Code and Code Verifier to Token Endpoint

Additional parameter sent to Token Endpoint:

| Parameter | Required | Description |
|-----------|----------|-------------|
| `code_verifier` | YES | The original code verifier |

### 4.6 Server Verifies code_verifier Before Returning Tokens

The token endpoint:
- Receives code_verifier from client
- Retrieves the stored code_challenge and code_challenge_method for this authorization code
- Transforms the received code_verifier using the stored method:
  - If S256: `BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))`
  - If plain: uses code_verifier directly
- Compares transformed value with stored code_challenge
- **If equal:** Continues normal OAuth 2.0 token issuance
- **If NOT equal:** Returns `invalid_grant` error (Section 5.2 of RFC 6749)

## Error Handling

| Scenario | Error | Description |
|----------|-------|-------------|
| Missing code_challenge (server requires PKCE) | `invalid_request` | PKCE code challenge required |
| Unsupported code_challenge_method | `invalid_request` | Transform algorithm not supported |
| code_verifier does not match | `invalid_grant` | Proof of possession failed |

## Security Considerations

### 7.1 Entropy of the code_verifier
- The code_verifier MUST be cryptographically random with high entropy
- RECOMMENDED: minimum 256 bits of entropy
- Attacker must not be able to guess or learn the value

### 7.2 Protection against Eavesdroppers
- Clients MUST NOT downgrade from "S256" to "plain" after trying "S256"
- "S256" protects against eavesdropping because the challenge cannot be used without the verifier
- "plain" does NOT protect against eavesdropping (code_challenge = code_verifier)
- "plain" SHOULD NOT be used in new implementations

### 7.3 Salting the code_challenge
- Salting is NOT used - code_verifier contains sufficient entropy (256 bits)
- Concatenating a publicly known value and hashing does not increase security

### 7.4 OAuth Security Considerations
- PKCE does not change OAuth 2.0 threat model
- Implementations must still follow OAuth 2.0 security requirements

### 7.5 TLS Security Considerations
- Transport Layer Security remains essential
- PKCE provides additional protection but does not replace TLS

## IANA Registrations

### OAuth Parameters Registry
- `code_verifier` - Token request parameter
- `code_challenge` - Authorization request parameter
- `code_challenge_method` - Authorization request parameter

### PKCE Code Challenge Method Registry
- `plain` - Direct use of code_verifier as code_challenge
- `S256` - SHA256 hash of code_verifier, base64url-encoded

## Compatibility

- Servers MAY accept clients that don't implement PKCE
- If code_verifier is not received, servers revert to standard OAuth 2.0 flow
- Client implementations SHOULD send PKCE parameters to all servers
- Server responses are unchanged from RFC 6749

## Key Terms

| Term | Definition |
|------|------------|
| **code_verifier** | Cryptographically random string used to correlate authorization request to token request |
| **code_challenge** | Challenge derived from code_verifier, sent in authorization request |
| **code_challenge_method** | Method used to derive code_challenge from code_verifier |
| **PKCE** | Proof Key for Code Exchange |
| **S256** | Code challenge method using SHA-256 hash |

## Quick Reference

| Section | Title |
|---------|-------|
| 1 | Introduction |
| 1.1 | Protocol Flow |
| 3 | Terminology |
| 4 | Protocol |
| 4.1 | Client Creates a Code Verifier |
| 4.2 | Client Creates the Code Challenge |
| 4.3 | Client Sends the Code Challenge |
| 4.4 | Server Returns the Code |
| 4.5 | Client Sends Authorization Code and Code Verifier |
| 4.6 | Server Verifies code_verifier |
| 5 | Compatibility |
| 6 | IANA Considerations |
| 7 | Security Considerations |
| Appendix A | Base64url Encoding without Padding |
| Appendix B | Example for S256 |

## Implementation Checklist

- [ ] Generate code_verifier with 43-128 characters, 256+ bits entropy
- [ ] Create code_challenge using S256 method (SHA-256 + base64url)
- [ ] Send code_challenge + code_challenge_method="S256" in auth request
- [ ] Store code_verifier securely (not in browser history/URL)
- [ ] Send code_verifier in token request
- [ ] Handle invalid_grant errors appropriately
- [ ] Never use "plain" method in new implementations

## Related RFCs

- **RFC 6749**: The OAuth 2.0 Authorization Framework (base specification)
- **RFC 6819**: OAuth 2.0 Threat Model and Security Considerations
- **RFC 7617**: The 'Basic' HTTP Authentication Scheme
- **RFC 8252**: OAuth 2.0 for Native Apps (uses PKCE)

## Full RFC Text

See [references/RFC7636.txt](references/RFC7636.txt) for the complete document.
