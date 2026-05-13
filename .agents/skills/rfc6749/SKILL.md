---
name: rfc6749
description: "RFC 6749: The OAuth 2.0 Authorization Framework. Defines the protocol for third-party application access to HTTP services on behalf of a resource owner, introducing authorization layers, access tokens, and refresh tokens. Replaces OAuth 1.0 (RFC 5849)."
---

# RFC 6749: The OAuth 2.0 Authorization Framework

**Obsoletes:** RFC 5849 (OAuth 1.0)
**Published:** October 2012
**Status:** Standards Track
**Author:** D. Hardt (Editor), Microsoft

The OAuth 2.0 authorization framework enables a third-party application to obtain limited access to an HTTP service. It allows access either on behalf of the resource owner (by orchestrating an approval interaction) or on behalf of the application itself.

## When to Use This Skill

Use this skill when working with:

- OAuth 2.0 authentication and authorization flows
- Access token issuance and validation
- Authorization code, implicit, password, or client credentials grants
- Third-party API access delegation
- Protected resource access patterns
- OAuth 2.0 protocol implementation or debugging

## Roles

OAuth 2.0 defines four roles:

| Role                     | Description                                                                                                                  |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------- |
| **Resource Owner**       | Entity capable of granting access to a protected resource. When a person, referred to as an end-user.                        |
| **Resource Server**      | Server hosting the protected resources, accepts and responds to protected resource requests using access tokens.             |
| **Client**               | Application making protected resource requests on behalf of the resource owner and with its authorization.                   |
| **Authorization Server** | Server issuing access tokens to the client after successfully authenticating the resource owner and obtaining authorization. |

## Protocol Flow

```
+--------+                               +---------------+
|        |--(A)- Authorization Request ->|   Resource    |
|        |                               |     Owner     |
|        |<-(B)-- Authorization Grant ---|               |
|        |                               +---------------+
|        |                               +---------------+
|        |--(C)-- Authorization Grant -->| Authorization |
| Client |                               |     Server    |
|        |<-(D)----- Access Token -------|               |
|        |                               +---------------+
|        |                               +---------------+
|        |--(E)----- Access Token ------>|    Resource   |
|        |                               |     Server    |
|        |<-(F)--- Protected Resource ---|               |
+--------+                               +---------------+
```

1. **(A)** Client requests authorization from resource owner
2. **(B)** Client receives authorization grant
3. **(C)** Client requests access token from authorization server with the grant
4. **(D)** Authorization server validates and issues access token
5. **(E)** Client requests protected resource with access token
6. **(F)** Resource server validates token and serves request

## Authorization Grant Types

This specification defines four grant types:

### 1. Authorization Code

- Uses authorization server as intermediary
- Resource owner credentials never shared with client
- Provides client authentication and direct token transmission
- Preferred for web applications

### 2. Implicit

- Simplified flow for browser-based clients (JavaScript)
- Access token issued directly to client
- Deprecated in OAuth 2.1 due to security concerns

### 3. Resource Owner Password Credentials

- Client obtains token using resource owner's username/password
- Resource owner shares credentials directly with client
- **Use only when other flows are not viable**

### 4. Client Credentials

- Client authenticates with its own credentials
- Used when client is acting on its own behalf, not on behalf of a user
- Suitable for machine-to-machine authentication

## Key Concepts

### Access Token

- A string representing authorization to access protected resources
- Contains scope, lifetime, and other access attributes
- Must be kept confidential
- Used by client to access resource server

### Refresh Token

- Credentials used to obtain new access tokens
- Issued alongside access token by authorization server
- Can be revoked independently
- Allows long-lived access without requiring resource owner interaction

### Scope

- Limits the extent of access granted
- Defined by authorization server
- Client requests specific scopes during authorization
- Resource server enforces scope limitations

### Redirection Endpoint

- URI to which authorization server redirects user-agent after authorization
- Must be registered with authorization server
- Used in authorization code and implicit flows

## Security Considerations (Section 10)

Key security topics covered:

- Client authentication requirements
- Client impersonation prevention
- Access token protection (bearer tokens)
- Refresh token security
- Authorization code protection
- Authorization code redirection URI manipulation
- Resource owner password credential handling
- Request confidentiality
- Endpoint authenticity verification
- Credentials-guessing attacks
- Phishing attacks
- CSRF protection
- Clickjacking prevention
- Code injection and input validation
- Open redirector prevention

## Protocol Endpoints

### Authorization Endpoint

- Used to obtain authorization from resource owner
- Handles authorization requests (Section 3.1)
- Returns authorization code or access token

### Token Endpoint

- Used by client to obtain access tokens (Section 3.2)
- Requires client authentication
- Returns access token, refresh token, and associated metadata

## Token Types

### Bearer Token (RFC 6750)

- Most commonly used token type
- No cryptographic requirements on the token itself
- Transport security (TLS) required

### MAC Token (Deprecated)

- Token includes embedded cryptographic key
- Allows resource server to validate without introspection

## Full RFC Text

See [references/RFC6749.txt](references/RFC6749.txt) for the complete document.

## Quick Reference

| Section | Title                         |
| ------- | ----------------------------- |
| 1       | Introduction                  |
| 1.1     | Roles                         |
| 1.2     | Protocol Flow                 |
| 1.3     | Authorization Grant           |
| 1.4     | Access Token                  |
| 1.5     | Refresh Token                 |
| 2       | Client Registration           |
| 3       | Protocol Endpoints            |
| 4       | Obtaining Authorization       |
| 5       | Issuing an Access Token       |
| 6       | Refreshing an Access Token    |
| 7       | Accessing Protected Resources |
| 10      | Security Considerations       |
| 11      | IANA Considerations           |

## Related RFCs

- **RFC 5849**: OAuth 1.0 (Obsoleted by this document)
- **RFC 6750**: The OAuth 2.0 Authorization Framework: Bearer Token Usage
- **RFC 6819**: OAuth 2.0 Threat Model and Security Considerations
- **RFC 7009**: OAuth 2.0 Token Revocation
- **RFC 7617**: The 'Basic' HTTP Authentication Scheme (Client Authentication)
- **RFC 7662**: OAuth 2.0 Token Introspection
