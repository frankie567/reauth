---
name: webauthn-2
description: "Web Authentication Level 2 (WebAuthn) - W3C specification defining an API for strong, attested, scoped public key-based credentials. Enables passwordless authentication and phishing-resistant MFA using platform or roaming authenticators. Use when working with WebAuthn API, FIDO2, public key credentials, or browser-based authentication."
---

# Web Authentication Level 2 (WebAuthn)

**Title:** Web Authentication: An API for accessing Public Key Credentials Level 2  
**Editors:** Jeff Hodges, J.C. Jones, Michael B. Jones, Akshay Kumar, Emil Lundberg  
**Published:** 8 April 2021 (W3C Recommendation)  
**Status:** W3C Recommendation  
**Source:** [W3C WebAuthn Level 2](https://www.w3.org/TR/2021/REC-webauthn-2-20210408/)

## Abstract

Web Authentication (WebAuthn) Level 2 defines a web API enabling the creation and use of strong, attested, scoped, public key-based credentials by web applications for the purpose of strongly authenticating users. The API allows web applications (Relying Parties) to register and authenticate users using public key credentials bound to authenticators. Authenticators are responsible for ensuring no operation is performed without user consent and can provide cryptographic proof of their properties to Relying Parties via attestation.

This specification defines the functional model for WebAuthn-conformant authenticators, including their signature and attestation functionality, and extends the Credential Management API to support public key credentials.

## Quick Reference

| Aspect | Details |
|--------|---------|
| **Specification Type** | W3C Recommendation |
| **Current Version** | Level 2 |
| **Previous Version** | Level 1 (2019) |
| **API** | `navigator.credentials.create()`, `navigator.credentials.get()` |
| **Credential Type** | Public Key Credentials (`public-key`) |
| **Authenticator Types** | Platform, Roaming |
| **Key Algorithms** | ES256, RS256, PS256, EdDSA, ES384, ES512 |
| **Attestation Types** | None, Basic, Self, AttCA, AnonCA |
| **Transport Types** | usb, nfc, ble, internal |

## Key Concepts

### Core Entities

**Public Key Credential:** A credential based on asymmetric cryptography where the public key is registered with a Relying Party and the private key is stored securely in an authenticator. Consists of a credential ID, credential public key, and credential private key.

**Authenticator:** A cryptographic entity (hardware or software) that can register a user with a Relying Party and later assert possession of the registered credential. Can be a platform authenticator (built into the device) or a roaming authenticator (external device like a security key).

**WebAuthn Relying Party (RP):** The entity whose web application uses the Web Authentication API to register and authenticate users. Consists of client-side script and server-side component.

**Client / User Agent:** The browser or application that mediates between the Relying Party and authenticators. Handles communication and user interaction.

### Credential Lifecycle

**Registration Ceremony:** The ceremony where a user, Relying Party, and client (with authenticator) work together to create a public key credential and associate it with the user's account. Requires user consent via an authorization gesture.

**Authentication Ceremony:** The ceremony where a user and client work to cryptographically prove to a Relying Party that the user controls the credential private key of a previously registered public key credential. Also requires user consent.

### User Verification

**User Present (UP):** A simple test of user presence (e.g., touching a device). Does not verify identity.

**User Verified (UV):** Local authorization via biometric recognition, PIN, password, or other method that distinguishes individual users.

**Authorization Gesture:** Physical interaction by a user with an authenticator (PIN, biometric, button press) that provides consent for a ceremony.

### Scoping and Privacy

**Scope:** Credentials are scoped to a specific Relying Party identifier (RP ID), typically the effective domain of the origin. A credential can only be used with the same RP ID it was registered with.

**RP ID:** A valid domain string identifying the WebAuthn Relying Party. Defaults to the caller's origin effective domain.

**Credential ID:** A probabilistically-unique byte sequence identifying a public key credential source. Used to look up credentials for use.

## API Overview

### Primary Interfaces

#### PublicKeyCredential
Extends the `Credential` interface with public key-specific properties:
- `rawId` (ArrayBuffer): The credential ID
- `response` (AuthenticatorResponse): Authenticator's response
- `getClientExtensionResults()`: Returns extension results

#### AuthenticatorResponse
Base interface for authenticator responses:
- `clientDataJSON` (ArrayBuffer): JSON-serialized client data

#### AuthenticatorAttestationResponse
Response for credential creation:
- `attestationObject` (ArrayBuffer): Contains authenticator data and attestation statement
- `getTransports()`: Returns supported transport types
- `getAuthenticatorData()`: Returns authenticator data
- `getPublicKey()`: Returns credential public key as SubjectPublicKeyInfo
- `getPublicKeyAlgorithm()`: Returns COSE algorithm identifier

#### AuthenticatorAssertionResponse
Response for authentication assertions:
- `authenticatorData` (ArrayBuffer): Signed authenticator data
- `signature` (ArrayBuffer): Signature over authenticator data and client data hash
- `userHandle` (ArrayBuffer): Opaque identifier for the user

### Method Signatures

```javascript
// Registration (Create a new credential)
navigator.credentials.create({ 
  publicKey: PublicKeyCredentialCreationOptions 
}).then((credential) => { /* PublicKeyCredential */ });

// Authentication (Use existing credential)
navigator.credentials.get({ 
  publicKey: PublicKeyCredentialRequestOptions 
}).then((assertion) => { /* PublicKeyCredential */ });

// Check for platform authenticator
PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
  .then((available) => { /* boolean */ });
```

### Options Dictionaries

#### PublicKeyCredentialCreationOptions (for registration)
```javascript
{
  rp: { name: string, id?: string },           // Relying Party info
  user: { 
    id: BufferSource,                           // User handle (max 64 bytes)
    name: string,                              // Human-readable name
    displayName: string                        // Display name
  },
  challenge: BufferSource,                     // Server-generated challenge
  pubKeyCredParams: [                          // Supported algorithms
    { type: "public-key", alg: COSEAlgorithmIdentifier }
  ],
  timeout?: number,                           // Operation timeout (ms)
  excludeCredentials?: [PublicKeyCredentialDescriptor],
  authenticatorSelection?: AuthenticatorSelectionCriteria,
  attestation?: AttestationConveyancePreference, // "none", "indirect", "direct", "enterprise"
  extensions?: AuthenticationExtensionsClientInputs
}
```

#### PublicKeyCredentialRequestOptions (for authentication)
```javascript
{
  challenge: BufferSource,                     // Server-generated challenge
  timeout?: number,
  rpId?: string,                              // RP ID override
  allowCredentials?: [PublicKeyCredentialDescriptor],
  userVerification?: UserVerificationRequirement, // "required", "preferred", "discouraged"
  extensions?: AuthenticationExtensionsClientInputs
}
```

#### AuthenticatorSelectionCriteria
```javascript
{
  authenticatorAttachment?: AuthenticatorAttachment, // "platform", "cross-platform"
  residentKey?: ResidentKeyRequirement,       // "discouraged", "preferred", "required"
  requireResidentKey?: boolean,                // Legacy flag
  userVerification?: UserVerificationRequirement
}
```

## Algorithm Support

### COSE Algorithm Identifiers
WebAuthn uses COSE algorithm identifiers registered in the IANA COSE Algorithms registry:

| Algorithm | COSE ID | Description |
|-----------|---------|-------------|
| ES256 | -7 | ECDSA with SHA-256 on P-256 |
| ES384 | -35 | ECDSA with SHA-384 on P-384 |
| ES512 | -36 | ECDSA with SHA-512 on P-521 |
| RS256 | -257 | RSASSA-PKCS1-v1_5 with SHA-256 |
| RS384 | -258 | RSASSA-PKCS1-v1_5 with SHA-384 |
| RS512 | -259 | RSASSA-PKCS1-v1_5 with SHA-512 |
| PS256 | -37 | RSASSA-PSS with SHA-256 |
| PS384 | -38 | RSASSA-PSS with SHA-384 |
| PS512 | -39 | RSASSA-PSS with SHA-512 |
| EdDSA | -8 | Ed25519 signature algorithm |

### Cryptographic Requirements
- All keys MUST be generated by the authenticator
- Keys MUST be scoped to a specific RP ID
- Private keys MUST never leave the authenticator
- Public keys are returned to the RP in COSE_Key format

## Authenticator Model

### Authenticator Data Structure
The authenticator data is a byte array (minimum 37 bytes) containing:

| Field | Size | Description |
|-------|------|-------------|
| rpIdHash | 32 bytes | SHA-256 hash of the RP ID |
| flags | 1 byte | UP, UV, AT, ED flags |
| signCount | 4 bytes | Signature counter (big-endian) |
| attestedCredentialData | variable | If AT flag is set |
| extensions | variable | If ED flag is set |

**Flags:**
- Bit 0 (UP): User Present - user is present
- Bit 2 (UV): User Verified - user has been verified
- Bit 6 (AT): Attested credential data included
- Bit 7 (ED): Extension data included

### Attested Credential Data
Contains:
- AAGUID (16 bytes): Authenticator identifier
- credentialIdLength (2 bytes): Length of credential ID
- credentialId (variable): The credential ID
- credentialPublicKey (variable): COSE_Key formatted public key

### Attestation
Attestation provides cryptographic proof of authenticator properties and credential provenance. The attestation object contains:
- authData: Authenticator data
- fmt: Attestation format identifier
- attStmt: Attestation statement

#### Attestation Types
- **None:** No attestation provided
- **Self (Surrogate Basic):** Authenticator signs with the credential private key
- **Basic (Batch):** Same attestation key pair shared across a batch of authenticators
- **AttCA (Attestation CA):** Uses TPM with attestation identity key pairs
- **AnonCA (Anonymization CA):** Dynamic per-credential attestation certificates

#### Defined Attestation Formats
- **packed:** Compact CBOR-based format (most common)
- **tpm:** TPM-based attestation
- **android-key:** Android Key Attestation
- **android-safetynet:** Android SafetyNet-based
- **fido-u2f:** FIDO U2F compatibility format
- **apple:** Apple anonymous attestation
- **none:** No attestation statement

## Security Considerations

### Cryptographic Challenges
- Challenges MUST be randomly generated by the RP (at least 16 bytes)
- Challenges MUST be stored server-side and verified
- Never accept a challenge that doesn't match what was sent

### Signature Counter
- Authenticators SHOULD implement per-credential signature counters
- Counters MUST increment with each successful authentication
- If new counter <= stored counter, possible cloned authenticator

### Attestation Considerations
- Attestation validates during registration only
- RP MUST verify attestation according to its policy
- Attestation doesn't protect against MITM during registration
- Subsequent authentications are MITM-resistant

### Credential Management
- Multiple credentials SHOULD be allowed per user
- Credential loss = key loss (no backup mechanism in spec)
- Users should register multiple authenticators

### User Verification
- UV flag indicates local verification occurred
- RP cannot verify biometric data itself
- Trust in UV depends on authenticator's attestation

## Privacy Considerations

### De-anonymization Prevention
- Credential IDs are scoped to RP ID
- Client prevents silent credential discovery
- Credentials are not enumerable across RPs

### User Handle
- MUST NOT contain personally identifying information
- Recommended: 64 random bytes
- Stored by RP, not displayed to user

### Username Enumeration
- RP MUST NOT leak which usernames have credentials
- Use out-of-band verification for registration
- Return plausible dummy values for non-existent accounts

### Attestation Privacy
- Batch attestation recommended (100K+ devices per cert)
- Anonymization CA can provide per-credential attestation
- AAGUID should not uniquely identify individual devices

## Extensions

WebAuthn supports extensions for additional functionality:

| Extension | ID | Purpose |
|-----------|-----|---------|
| AppID | `appid` | FIDO U2F compatibility for existing credentials |
| AppID Exclusion | `appidExclude` | Exclude U2F credentials during registration |
| User Verification Method | `uvm` | Report which UV methods were used |
| Credential Properties | `credProps` | Report if credential is discoverable |
| Large Blob | `largeBlob` | Store opaque data with credential |

## When to Use This Skill

Use this skill when:
- Implementing WebAuthn-based authentication in a web application
- Designing passwordless or phishing-resistant authentication flows
- Integrating with FIDO2 authenticators (security keys, platform authenticators)
- Evaluating security of WebAuthn implementations
- Working with PublicKeyCredential API
- Implementing or verifying attestation
- Designing multi-factor authentication with WebAuthn
- Understanding browser-based public key authentication
- Working with CTAP2 (Client to Authenticator Protocol)
- Implementing WebAuthn extensions

## Reference Implementation

Browsers implement WebAuthn natively:
- Chrome: Supported since Chrome 67+
- Firefox: Supported since Firefox 60+
- Safari: Supported since Safari 13+
- Edge: Supported since Edge 79+

## Related Standards

- **FIDO2:** Overall framework combining WebAuthn and CTAP
- **CTAP2:** Client to Authenticator Protocol v2
- **FIDO U2F:** Legacy FIDO Universal Second Factor (backwards compatible)
- **Credential Management API:** W3C spec extended by WebAuthn
- **RFC 8152:** COSE (CBOR Object Signing and Encryption)
- **RFC 8949:** CBOR (Concise Binary Object Representation)
- **RFC 8610:** CDDL (CBOR Data Definition Language)
- **IANA COSE Algorithms Registry:** Algorithm identifiers
- **FIDO Metadata Service:** Authenticator metadata

## Level 2 Additions (vs Level 1)

WebAuthn Level 2 adds:
1. `getPublicKey()` and `getAuthenticatorData()` methods on AuthenticatorAttestationResponse
2. `isUserVerifyingPlatformAuthenticatorAvailable()` static method
3. Additional attestation statement formats (android-key, android-safetynet, apple)
4. Extension mechanism for future functionality
5. Enhanced privacy considerations
6. WebDriver automation support
7. Support for large blob storage extension

## Full Specification Text

See [references/webauthn-2.html](references/webauthn-2.html) for the complete W3C Recommendation.
