---
name: rfc9700
description: "RFC 9700: Best Current Practice for OAuth 2.0 Security (BCP 240). Updates RFCs 6749, 6750, and 6819 with security requirements for OAuth clients, authorization servers, and resource servers. Use when implementing or reviewing OAuth or OpenID Connect flows, PKCE and downgrade prevention, redirect URI validation, CSRF and mix-up defenses, access token restrictions, refresh token rotation, or migration away from implicit and password grants."
---

# RFC 9700: Best Current Practice for OAuth 2.0 Security

**Category:** Best Current Practice (BCP 240)  
**Published:** January 2025  
**Updates:** RFC 6749, RFC 6750, RFC 6819

This RFC complements the original OAuth security guidance and deprecates insecure modes of operation. Apply its updated requirements when older OAuth specifications permit weaker behavior.

## Using This Reference

Identify the component (client, authorization server, or resource server), client type (public or confidential), grant, and whether multiple issuers are supported. Read the relevant sections of [the full RFC](references/RFC9700.txt) before implementing or assessing a requirement. Preserve the distinction between MUST, SHOULD, and MAY, including each requirement's conditions and exceptions.

Use §2 for the baseline, §3 for attacker capabilities, and §4 for attack details and additional requirements. The attacker model includes malicious clients and servers, network attackers, leaked authorization requests or responses, and stolen access tokens; TLS alone does not cover all of them.

## Quick Reference

| Area | Requirement or recommendation | Sections |
|---|---|---|
| Redirect URIs | Authorization servers MUST compare registered URIs using exact string matching, with the native-app localhost port exception. | 2.1, 4.1.3 |
| Code flow | Public clients MUST use PKCE; PKCE is RECOMMENDED for confidential clients. Authorization servers MUST support it and expose a way to detect support. | 2.1.1 |
| PKCE method | Clients SHOULD use a method that conceals the verifier in the authorization request; the RFC identifies `S256` as the available method. | 2.1.1 |
| Implicit flow | Clients SHOULD NOT use `token` or other response types returning access tokens in the authorization response unless injection and leakage risks are mitigated. Prefer code flow. | 2.1.2 |
| Password grant | The resource owner password credentials grant MUST NOT be used. | 2.4 |
| CSRF | Clients MUST prevent CSRF using correctly bound PKCE, OIDC nonce, or one-time `state`, subject to the conditions below. | 2.1, 4.7 |
| Multiple issuers | Clients interacting with multiple authorization servers MUST prevent mix-up attacks. | 2.1, 4.4 |
| Access tokens | Sender constraints and minimal privileges, including audience restrictions, are SHOULD-level recommendations. Resource servers MUST reject a token intended for a different audience. | 2.2.1, 2.3, 4.9–4.10 |
| Refresh tokens | Public-client refresh tokens MUST use sender constraints or rotation to detect replay. | 2.2.2, 4.14 |
| Client authentication | Enforce it where credential provisioning and confidentiality are feasible (SHOULD); asymmetric methods such as mTLS or `private_key_jwt` are RECOMMENDED. | 2.5 |
| Token transport | Clients MUST NOT send access tokens in URI query parameters. | 4.3.2 |

## Authorization Code, PKCE, and CSRF

- Bind each PKCE challenge or OIDC nonce to one transaction, the client, and the initiating user agent; these bindings are MUST-level requirements (§2.1.1).
- At the authorization server, bind the challenge and its presence to the issued code. A code issued with a challenge requires a valid verifier at redemption. A token request containing a verifier for a code issued without a challenge MUST be rejected; silently ignoring that verifier permits downgrade attacks (§4.8.2).
- Publish `code_challenge_methods_supported` in authorization server metadata (RECOMMENDED), or provide another deployment-specific way to establish PKCE support (§2.1.1).
- Clients MUST establish server support before relying on PKCE for CSRF protection. Otherwise use OIDC nonce or a one-time `state` value securely bound to the user agent. If `state` carries application data whose integrity matters, protect it against tampering and swapping even when PKCE provides CSRF protection (§4.7.1).
- Confidential OIDC clients MAY use nonce instead of PKCE for code-injection protection, with the precautions in §4.5.3.2: validate the nonce in the ID Token from the token endpoint, even if an ID Token arrived in the authorization response, and disregard all issued tokens until validation succeeds. Nonce does not replace PKCE for public clients.
- Client authentication alone does not prevent code injection. Preserve RFC 6749's client binding and token-endpoint `redirect_uri` checks; matching a registered URI does not replace comparing with the URI used for that code's authorization request (§4.5.2).
- Codes MUST be invalidated after first redemption; on a second redemption attempt, the server SHOULD revoke tokens already issued from that code (§4.2.4).

## Redirects and Issuer Binding

Use simple string comparison for registered redirect URIs, without wildcard or pattern matching. Native apps using localhost redirection MUST be allowed variable ports under RFC 8252. Section 4.1.3 also permits trusting a redirect URI when the authorization request's origin and integrity are verified, for example with authenticated JAR or PAR; read that exception before applying it.

For multiple issuers, store the expected issuer for each request and bind it to the user agent. Prefer the authorization-response `iss` parameter (RFC 9207), or a corresponding issuer value in an ID Token or JARM authorization response. Compare it against the stored issuer and abort on mismatch. Merely storing an authorization endpoint URL is insufficient to bind the authorization and token endpoints (§4.4.2).

Distinct redirect URIs per issuer are a fallback when other defenses are unavailable. Compare the actual callback URI with the stored issuer's expected URI and abort on mismatch; consult §4.4.2.2 for registration-related limitations.

Clients and authorization servers MUST NOT expose open redirectors. An invalid `client_id`/`redirect_uri` combination MUST NOT cause an automatic redirect. Even a registered URI can be a phishing destination; consult §4.11.2 for authentication and trust requirements before redirecting on errors, consent denial, or silent authentication.

## Access and Refresh Tokens

For access tokens, prefer sender constraints using mTLS (RFC 8705) or DPoP (RFC 9449), and restrict audience, resources, actions, and scope. Resource servers must enforce applicable restrictions on every request. Client authentication and sender-constrained tokens serve different purposes: signing a client assertion does not itself constrain an access token (§§2.2–2.5, 4.10).

Resource servers MUST protect access tokens as secrets and avoid plaintext storage or transfer (§4.9.3). Sender constraints lose effectiveness if the attacker also obtains or can use the associated key (§4.10.1).

For refresh tokens (§4.14.2):

- The authorization server MUST assess whether to issue them and MUST bind issued tokens to the consented scope and resource servers. Confidential clients retain the RFC 6749 client-binding requirement.
- For public clients, use cryptographic sender binding or rotation. Rotation issues a replacement on each refresh, invalidates the previous token, and retains the relationship so replay of an invalidated token can trigger revocation of the active refresh token. Replacing a token without retaining replay detection is insufficient.
- If grant information is encoded in a refresh token, its integrity MUST be protected.
- Tokens SHOULD expire after inactivity; the RFC leaves the duration to server policy. Revocation on password change or authorization-server logout is MAY-level guidance.

## Browser and Deployment Controls

| Concern | Guidance | Sections |
|---|---|---|
| Response transport | Authorization responses MUST NOT traverse unencrypted network connections. HTTP redirect URIs are forbidden except native-client loopback redirects under RFC 8252. | 2.6 |
| Referrer and history leakage | Avoid third-party resources and external links on authorization and callback pages (SHOULD NOT). Consider `Referrer-Policy: no-referrer` and form-post response mode. | 4.2–4.3 |
| Credential-bearing redirects | Authorization servers MUST NOT use HTTP 307 when a redirected request might contain user credentials; HTTP 303 is RECOMMENDED for HTTP redirects in this case. | 4.12 |
| TLS termination | Proxies MUST sanitize security-relevant inbound headers. Protect the proxy-to-application connection against eavesdropping, injection, and replay, and authenticate the communicating entities. | 4.13 |
| Client/user identity confusion | If identifiers share a namespace, clients SHOULD NOT influence claims that could impersonate resource owners. If unavoidable, the server MUST give resource servers another way to distinguish token types. | 4.15 |
| Clickjacking | Authorization servers MUST prevent it; CSP level 2 or later is RECOMMENDED across authorization, login, and related pages. Read §4.16 for framing policy and additional defenses. | 4.16 |
| `postMessage` | Both sides MUST verify origins using exact matching. Send only to trusted client origins, never `*`, and retain all redirect-flow protections. | 4.17 |
| CORS | Browser-accessed token, metadata, JWKS, and registration endpoints MAY support CORS; the authorization endpoint MUST NOT. | 2.6 |
| Metadata | Publishing and using RFC 8414 authorization server metadata is RECOMMENDED. | 2.6 |

## Full RFC Text

Read [references/RFC9700.txt](references/RFC9700.txt) for the complete specification, including attack examples and normative exceptions. Search by section number or terms such as `PKCE Downgrade`, `Mix-Up`, or `Refresh Token Protection`.

Source: [RFC Editor — RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html).
