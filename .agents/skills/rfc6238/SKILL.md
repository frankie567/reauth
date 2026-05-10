---
name: rfc6238
description: "RFC 6238 - TOTP: Time-Based One-Time Password Algorithm. Extends HOTP (RFC 4226) by using time as the moving factor instead of a counter, enabling time-synchronized OTP generation. Use when working with TOTP, time-based authentication, Google Authenticator, or OATH time-based standards."
---

# RFC 6238: TOTP Algorithm

**Title:** TOTP: Time-Based One-Time Password Algorithm  
**Authors:** D. M'Raihi, S. Machani, M. Pei, J. Rydell  
**Published:** May 2011  
**Category:** Informational  
**Source:** [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238.txt)

## Abstract

RFC 6238 describes an extension of the HOTP (HMAC-Based One-Time Password) algorithm defined in RFC 4226 to support a time-based moving factor. While HOTP uses an event counter as the moving factor, TOTP replaces this with a time value derived from the current Unix time and a configurable time step.

The time-based variant provides short-lived OTP values (typically valid for 30 seconds), which are desirable for enhanced security. The algorithm maintains interoperability with HOTP and can be used across VPN access, Wi-Fi network logon, and transaction-oriented web applications.

## Quick Reference

| Aspect | Details |
|--------|---------|
| **Algorithm** | Time-Based One-Time Password (TOTP) |
| **Base Algorithm** | HOTP (RFC 4226) with HMAC |
| **Type** | Time-based (Unix timestamp) |
| **Default Time Step** | 30 seconds |
| **Purpose** | Two-factor authentication |
| **Use Cases** | VPN, Wi-Fi, web applications, mobile apps |
| **OATH Standard** | Yes |
| **Relation to HOTP** | Extension (replaces counter with time) |

## Key Concepts

### TOTP Algorithm Core
- **TOTP = HOTP(K, T)**: TOTP is mathematically equivalent to HOTP where the counter `C` is replaced by a time-based value `T`
- **Time Step (X)**: Configurable duration in seconds (default: 30 seconds) that defines the validity window of each OTP
- **Unix Time**: Number of seconds elapsed since midnight UTC, January 1, 1970 (the Unix epoch)
- **Time Derivation**: T = floor((Current Unix Time - T0) / X), where T0 is the start time (default: 0)

### Time Calculation Formula

```
T = (Current Unix time - T0) / X
TOTP = HOTP(K, T)
```

Where:
- `K` = Shared secret key (same as HOTP)
- `T` = Number of time steps since T0
- `X` = Time step size in seconds (default: 30)
- `T0` = Unix time to start counting (default: 0, the Unix epoch)
- `HOTP` = The algorithm from RFC 4226

### Example
With default settings (X = 30 seconds, T0 = 0):
- At Unix time 0-29 seconds: T = 0, OTP value = HOTP(K, 0)
- At Unix time 30-59 seconds: T = 1, OTP value = HOTP(K, 1)
- At Unix time 60-89 seconds: T = 2, OTP value = HOTP(K, 2)

## Algorithm Requirements

The RFC specifies these requirements:

1. **R1**: Prover and verifier MUST know or derive current Unix time
2. **R2**: Prover and verifier MUST share the same secret or secret transformation
3. **R3**: Algorithm MUST use HOTP (RFC 4226) as the building block
4. **R4**: Prover and verifier MUST use the same time-step value X
5. **R5**: There MUST be a unique secret (key) for each prover
6. **R6**: Keys SHOULD be randomly generated or derived using key derivation
7. **R7**: Keys SHOULD be stored securely (tamper-resistant, access-controlled)

## Security Considerations

### Inherited Security
TOTP inherits all security properties from HOTP (RFC 4226):
- Based on HMAC (RFC 2104) which provides cryptographic strength
- Dynamic truncation produces uniformly distributed OTP values
- Best possible attack is brute force

### Validation and Time-Step Size
- **Validation Window**: Server should accept OTPs within a reasonable delay window (recommendation: at most one time step for network delay)
- **Default Recommendation**: 30-second time step balances security and usability
- **Security vs. Usability Tradeoff**: 
  - Larger time steps = larger attack window but better usability
  - Smaller time steps = better security but requires more frequent OTP regeneration
- **Replay Protection**: Server MUST NOT accept the same OTP multiple times within its validity window

### Clock Drift and Resynchronization
- **Clock Drift**: Differences between client and server clocks can cause validation failures
- **Resynchronization**: Validator SHOULD allow for configurable time-step drift (forward and backward from current time)
- **Drift Threshold**: Recommended limit prevents excessive validation attempts
- **Explicit Resynchronization**: For large drifts, additional authentication measures may be required

### Key Management
- Keys SHOULD be randomly generated using cryptographically strong methods (RFC 4086)
- Keys SHOULD be the same length as the HMAC output
- Keys SHOULD be stored securely using tamper-resistant hardware
- Access to key material MUST be limited to required processes only

## Hash Function Support

While HOTP (RFC 4226) specifies HMAC-SHA-1, TOTP implementations MAY use:
- **HMAC-SHA-1** (160-bit) - Baseline requirement
- **HMAC-SHA-256** (256-bit) - Recommended for new implementations
- **HMAC-SHA-512** (512-bit) - For highest security requirements

## Comparison: TOTP vs HOTP

| Feature | HOTP (RFC 4226) | TOTP (RFC 6238) |
|---------|-----------------|-----------------|
| Moving Factor | Event counter | Unix time |
| Validity | Until next event | Time step duration |
| Synchronization | Counter-based | Clock-based |
| Typical Use | Hardware tokens | Mobile apps, software |
| Drift Handling | Counter resync | Clock drift tolerance |
| Example | YubiKey | Google Authenticator |

## When to Use This Skill

Use this skill when:
- Implementing or working with TOTP-based authentication systems
- Designing time-based two-factor authentication solutions
- Integrating with Google Authenticator, Authy, or similar TOTP apps
- Evaluating security of time-based OTP implementations
- Working with OATH-compliant time-based tokens
- Migrating from HOTP to TOTP or vice versa
- Studying the differences between time-based and counter-based OTP

## Reference Implementation

Appendix A of RFC 6238 includes reference implementations and Appendix B provides test vectors for verification.

## Related Standards

- **RFC 4226**: HOTP (HMAC-Based One-Time Password) - The base algorithm TOTP extends
- **RFC 2104**: HMAC: Keyed-Hashing for Message Authentication - Underlying cryptographic primitive
- **RFC 2119**: Key words for use in RFCs to Indicate Requirement Levels
- **RFC 4086**: Randomness Recommendations for Security
- **RFC 5246**: TLS Protocol - Recommended secure channel for provisioning
- **RFC 6030**: PSKC (Portable Symmetric Key Container) - Key provisioning format

## Full RFC Text

See [references/RFC6238.txt](references/RFC6238.txt) for the complete document.
