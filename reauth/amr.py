"""Authentication Method Reference Values (amr) per RFC 8176.

This module defines the standard Authentication Method Reference values
as specified in RFC 8176 for use in JWT amr claims. These values represent
the authentication methods used in an authentication event.

See: https://datatracker.ietf.org/doc/html/rfc8176
"""

from enum import StrEnum


class AuthenticationMethodReference(StrEnum):
    """Standard Authentication Method Reference values (amr) per RFC 8176.

    These values are used in the 'amr' claim of JSON Web Tokens (JWT) to
    identify the authentication methods used in an authentication event.

    Each value represents a family of closely related authentication methods.
    The registry is maintained by IANA and is extensible.
    """

    # Biometric methods
    FACE = "face"
    """Facial recognition biometric authentication."""

    FPT = "fpt"
    """Fingerprint biometric authentication."""

    IRIS = "iris"
    """Iris scan biometric authentication."""

    RETINA = "retina"
    """Retina scan biometric authentication."""

    VBM = "vbm"
    """Voice biometric authentication."""

    # Knowledge-based methods
    KBA = "kba"
    """Knowledge-based authentication (e.g., security questions)."""

    PIN = "pin"
    """Personal Identification Number or pattern authentication."""

    PWD = "pwd"
    """Password-based authentication."""

    # Possession-based methods
    HWK = "hwk"
    """Proof-of-Possession of a hardware-secured key."""

    OTP = "otp"
    """One-time password (HOTP/TOTP)."""

    SC = "sc"
    """Smart card authentication."""

    SWK = "swk"
    """Proof-of-Possession of a software-secured key."""

    # Out-of-band methods
    SMS = "sms"
    """SMS text message confirmation."""

    TEL = "tel"
    """Telephone call confirmation."""

    EMAIL = "email"
    """Email-based OTP or magic link authentication.

    This is a custom extension to RFC 8176, not part of the standard.
    """

    OAUTH2 = "oauth2"
    """OAuth 2.0 authentication, including social login.

    This is a custom extension to RFC 8176, not part of the standard.
    """

    # Multi-factor and risk-based methods
    MFA = "mfa"
    """Multiple-factor authentication."""

    MCA = "mca"
    """Multiple-channel authentication."""

    RBA = "rba"
    """Risk-based authentication."""

    # Special purpose
    GEO = "geo"
    """Geolocation-based authentication."""

    USER = "user"
    """User presence test."""

    WIA = "wia"
    """Windows Integrated Authentication."""


__all__ = ["AuthenticationMethodReference"]
