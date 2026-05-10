---
name: rfc8176
description: RFC 8176 - Authentication Method Reference Values. Establishes IANA registry for amr claim values in JWT tokens, defining standard identifiers for authentication methods including biometrics (face, fingerprint, iris, retina, voice), password, OTP, MFA, smart card, SMS, and more. Use when working with JWT amr claims, authentication method identifiers, or OpenID Connect authentication context.
---

# RFC 8176: Authentication Method Reference Values

This skill provides access to **RFC 8176**, which defines standard Authentication Method Reference (amr) values for use in JSON Web Token (JWT) claims.

## When to Use This Skill

- When you need to understand or validate `amr` claim values in JWTs
- When implementing OpenID Connect authentication flows
- When designing or reviewing authentication systems that use standard method identifiers
- When you need the official IANA-registered authentication method reference values

## Quick Reference

The RFC defines the following standard `amr` values:

| Value | Description |
|-------|-------------|
| `face` | Facial recognition biometric |
| `fpt` | Fingerprint biometric |
| `geo` | Geolocation-based authentication |
| `hwk` | Proof-of-Possession of hardware-secured key |
| `iris` | Iris scan biometric |
| `kba` | Knowledge-based authentication |
| `mca` | Multiple-channel authentication |
| `mfa` | Multiple-factor authentication |
| `otp` | One-time password (HOTP/TOTP) |
| `pin` | Personal Identification Number or pattern |
| `pwd` | Password-based authentication |
| `rba` | Risk-based authentication |
| `retina` | Retina scan biometric |
| `sc` | Smart card |
| `sms` | SMS text message confirmation |
| `swk` | Proof-of-Possession of software-secured key |
| `tel` | Telephone call confirmation |
| `user` | User presence test |
| `vbm` | Voice biometric |
| `wia` | Windows integrated authentication |

## Full RFC Text

See [references/RFC8176.txt](references/RFC8176.txt) for the complete RFC document.

## Key Concepts

### amr Claim
The `amr` (Authentication Methods References) claim is a JSON array of strings that identify authentication methods used in an authentication event. Defined in OpenID Connect Core 1.0.

### Relationship to acr
- `acr` (Authentication Context Class Reference): Specifies business rules that authentications should satisfy
- `amr` (Authentication Methods References): Specifies particular authentication methods that were actually used
- `acr` states *what* rules were satisfied; `amr` states *how* they were satisfied

### Design Principles
- Values represent families of closely related methods (e.g., "otp" covers both HOTP and TOTP)
- Only distinctions known to be useful to relying parties are made
- Overly granular values hurt interoperability
- The registry is extensible - new values can be added via IANA registration

## IANA Registry

This RFC establishes the IANA "Authentication Method Reference Values" registry. New values require:
- Expert Review per RFC 5226
- Three-week review period on jwt-reg-review@ietf.org mailing list
- Designated Expert approval
