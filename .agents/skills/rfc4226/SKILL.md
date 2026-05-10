---
name: rfc4226
description: "RFC 4226 - HOTP: An HMAC-Based One-Time Password Algorithm. Defines the standard algorithm for generating one-time password values using HMAC. Use when working with HOTP, one-time passwords, HMAC-based authentication, two-factor authentication systems, or OATH standards."
---

# RFC 4226: HOTP Algorithm

**Title:** HOTP: An HMAC-Based One-Time Password Algorithm  
**Authors:** D. M'Raihi, M. Bellare, F. Hoornaert, D. Naccache, O. Ranen  
**Published:** December 2005  
**Category:** Informational  
**Source:** [RFC 4226](https://www.rfc-editor.org/rfc/rfc4226.txt)

## Abstract

RFC 4226 describes an algorithm to generate one-time password (OTP) values based on Hashed Message Authentication Code (HMAC). It provides a security analysis of the algorithm and discusses important parameters for secure deployment. The algorithm is designed for use across a wide range of network applications including remote VPN access, Wi-Fi network logon, and transaction-oriented web applications.

The HOTP algorithm is a joint effort by the OATH (Open AuTHentication) membership to specify a freely distributable algorithm that facilitates interoperability across commercial and open-source implementations, enabling broader adoption of two-factor authentication.

## Quick Reference

| Aspect | Details |
|--------|---------|
| **Algorithm** | HMAC-Based One-Time Password (HOTP) |
| **Base Algorithm** | HMAC (Hash-based Message Authentication Code) |
| **Type** | Event-based (counter-based) |
| **Purpose** | Two-factor authentication |
| **Use Cases** | VPN access, Wi-Fi logon, web applications |
| **OATH Standard** | Yes |

## Key Concepts

### HOTP Algorithm Core
- **HOTP Value Generation**: Uses HMAC-SHA-1 (or other hash functions) with a secret key and a counter
- **Counter-Based**: Each OTP is generated using a monotonically increasing counter value
- **Digit Length**: Typically produces 6-8 digit numeric codes (configurable)

### Algorithm Components
1. **Shared Secret**: A secret key known only to the token and validation server
2. **Counter**: A moving factor (event-based counter) that changes with each OTP generation
3. **HMAC**: Hash-based Message Authentication Code that combines secret and counter
4. **Dynamic Truncation**: Converts HMAC output to a numeric OTP value

### Security Properties
- Resistant to replay attacks (when properly implemented with counter synchronization)
- No plaintext password transmission
- Limited window for valid OTP usage
- Resilient against brute-force attacks (with proper digit length)

## Algorithm Description

The HOTP algorithm generates one-time passwords as follows:

```
HOTP(K, C) = Truncate(HMAC-SHA-1(K, C))
```

Where:
- `K` = Shared secret key
- `C` = Counter value (8-byte string in network byte order)
- `Truncate` = Dynamic truncation function that extracts a 31-bit string from HMAC output
- Final OTP = Truncated value modulo 10^Digits (where Digits is typically 6)

## Security Considerations

### Validation Requirements
- Server MUST validate OTP values against the expected counter window
- Server SHOULD implement throttling to prevent brute-force attacks
- Server SHOULD support counter resynchronization for token drift

### Resynchronization
The RFC defines methods for handling counter drift between the token and server:
- **Simple Resynchronization**: Accept OTP values within a look-ahead window
- **Counter-Based Resynchronization**: Use a special resynchronization OTP

### Threat Model
- **Brute Force**: Attacks are feasible with insufficient digit length; 6 digits provides ~1 million possibilities
- **Replay Attacks**: Mitigated by counter-based system and validation window
- **Man-in-the-Middle**: OTP alone doesn't prevent MITM; requires secure channel
- **Shared Secret Compromise**: Entire system security depends on secret key protection

## Extensions

### Composite Shared Secrets
Allows combining multiple shared secrets for enhanced security or migration scenarios.

### Bi-Directional Authentication
Enables mutual authentication where both client and server authenticate to each other.

### Variable Parameters
- **Number of Digits**: Can be configured from 6 to 8+ digits
- **Alphanumeric Values**: Can produce alphanumeric OTPs instead of numeric
- **Hash Function**: Can use SHA-256, SHA-512 in addition to SHA-1

## When to Use This Skill

Use this skill when:
- Implementing or working with HOTP-based authentication systems
- Designing two-factor authentication solutions
- Integrating with OATH-compliant hardware or software tokens
- Evaluating security of one-time password implementations
- Studying authentication algorithm design and security analysis
- Working with RFC 4226 directly or its implementations

## Reference Implementation

Appendix C of RFC 4226 includes reference implementations in pseudocode and test values for verification in Appendix D.

## Related Standards

- **OATH**: Open AuTHentication initiative - industry alliance behind HOTP
- **RFC 2119**: Key words for use in RFCs to Indicate Requirement Levels
- **RFC 3979**: IETF Intellectual Property Rights
- **RFC 6238**: TOTP (Time-based One-Time Password) - builds on HOTP concepts

## Full RFC Text

See [references/RFC4226.txt](references/RFC4226.txt) for the complete document.
