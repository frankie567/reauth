import dataclasses
import typing

from reauth.exceptions import ReauthException


@dataclasses.dataclass(frozen=True)
class TokenParts:
    identifier: str
    secret: str


@dataclasses.dataclass(frozen=True)
class GeneratedToken:
    token: str
    identifier: str
    verifier: str


class TokenException(ReauthException):
    """Base exception for token errors."""


class InvalidTokenException(TokenException):
    """Raised for malformed bearer tokens."""


class TokenGenerationException(TokenException):
    """Raised when token generation or verifier creation fails."""


class TokenVerificationException(TokenException):
    """Raised when verification or verifier upgrade cannot be completed."""


class TokenIdentifierCollision(TokenException):
    """Storage rejected an identifier; no credential was persisted."""


class TokenProvider(typing.Protocol):
    async def generate(self) -> GeneratedToken:
        """Generate credentials; raise TokenGenerationException on backend failure."""
        ...

    def parse(self, token: str) -> TokenParts:
        """Parse credentials; raise InvalidTokenException on malformed input."""
        ...

    async def verify_and_update(
        self, secret: str, verifier: str
    ) -> tuple[bool, str | None]:
        """Verify and optionally upgrade only on success.

        Invalid secrets return (False, None). Operational failures, including
        malformed or unsupported stored verifiers, raise TokenVerificationException.
        Implementations translate expected backend errors with their cause and
        offload blocking SDK calls. Programming errors and cancellation propagate.
        """
        ...


class TokenVerifier(typing.Protocol):
    async def create(self, secret: str) -> str:
        """Create a verifier; raise TokenGenerationException on backend failure."""
        ...

    async def verify_and_update(
        self, secret: str, verifier: str
    ) -> tuple[bool, str | None]:
        """Verify a secret and optionally return an upgraded verifier on success.

        Return (False, None) for invalid secrets, (True, None) for current
        verifiers, or (True, replacement) for a successful match needing upgrade.
        Malformed/unsupported stored verifiers and expected backend or upgrade
        failures raise TokenVerificationException with the backend cause.
        Offload blocking SDK calls; programming errors and cancellation propagate.
        """
        ...
