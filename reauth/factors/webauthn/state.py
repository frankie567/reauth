import abc
import dataclasses
import datetime
import typing

from reauth.exceptions import ReauthException
from reauth.logging import get_logger
from reauth.timestamp import get_current_timestamp
from reauth.tokens import (
    InvalidTokenException,
    TokenGenerationException,
    TokenIdentifierCollision,
    TokenProvider,
)

logger = get_logger(__name__)
type Ceremony = typing.Literal["enrollment", "authentication"]


class WebAuthnException(ReauthException):
    """Base exception for WebAuthn factor errors."""


class InvalidStateException(WebAuthnException):
    """The state is missing, expired, invalid, or belongs to another ceremony."""


@dataclasses.dataclass
class WebAuthnState:
    id: typing.Any | None
    token_identifier: str
    token_verifier: str
    rp_id: str
    factor_identifier: str
    ceremony: Ceremony
    session_id: typing.Any
    identity_id: typing.Any | None
    challenge: bytes
    allowed_credential_ids: list[str] | None
    expires_at: int


class WebAuthnStateService(abc.ABC):
    """Issue and consume single-use ceremony state in the caller's transaction."""

    def __init__(
        self,
        *,
        token_provider: TokenProvider,
        lifetime: datetime.timedelta = datetime.timedelta(minutes=5),
    ) -> None:
        self.token_provider = token_provider
        self.lifetime = lifetime

    async def create(
        self,
        *,
        rp_id: str,
        factor_identifier: str,
        ceremony: Ceremony,
        session_id: typing.Any,
        identity_id: typing.Any | None,
        challenge: bytes,
        allowed_credential_ids: list[str] | None = None,
    ) -> tuple[str, WebAuthnState]:
        """Store the challenge and its request context and return the opaque state token.

        Returns:
            The opaque token and pending ceremony state.

        Raises:
            ValueError: If the initiating session is missing.
            TokenGenerationException: If state identifiers repeatedly collide.
        """
        if session_id is None:
            message = "WebAuthn requires an initiating session"
            raise ValueError(message)
        for attempt in range(3):
            token = await self.token_provider.generate()
            state = WebAuthnState(
                id=None,
                token_identifier=token.identifier,
                token_verifier=token.verifier,
                rp_id=rp_id,
                factor_identifier=factor_identifier,
                ceremony=ceremony,
                session_id=session_id,
                identity_id=identity_id,
                challenge=challenge,
                allowed_credential_ids=allowed_credential_ids,
                expires_at=get_current_timestamp() + int(self.lifetime.total_seconds()),
            )
            try:
                state.id = await self.insert(state)
                break
            except TokenIdentifierCollision as error:
                if attempt == 2:
                    raise TokenGenerationException() from error
        logger.debug(
            "WebAuthn ceremony state created",
            extra={
                "identity_id": identity_id,
                "state_id": state.id,
                "ceremony": ceremony,
            },
        )
        return token.token, state

    async def consume(
        self,
        token: str,
        *,
        rp_id: str,
        factor_identifier: str,
        ceremony: Ceremony,
        session_id: typing.Any,
    ) -> WebAuthnState:
        """Validate and delete state bound to the current factor, ceremony and session.

        Returns:
            The consumed state. Deletion becomes durable on commit.

        Raises:
            InvalidStateException: If the token, binding or lifetime check fails.
        """
        try:
            parts = self.token_provider.parse(token)
        except InvalidTokenException:
            logger.warning(
                "Malformed WebAuthn state token", extra={"ceremony": ceremony}
            )
            raise InvalidStateException() from None
        state = await self.get_by_token_identifier(parts.identifier)
        if (
            state is None
            or state.expires_at <= get_current_timestamp()
            or state.rp_id != rp_id
            or state.factor_identifier != factor_identifier
            or state.ceremony != ceremony
            or state.session_id != session_id
        ):
            logger.warning(
                "Invalid WebAuthn ceremony state",
                extra={
                    "identity_id": state.identity_id if state is not None else None,
                    "ceremony": ceremony,
                },
            )
            raise InvalidStateException()
        valid, _ = await self.token_provider.verify_and_update(
            parts.secret, state.token_verifier
        )
        if not valid:
            logger.warning(
                "Invalid WebAuthn state token",
                extra={
                    "identity_id": state.identity_id,
                    "state_id": state.id,
                    "ceremony": ceremony,
                },
            )
            raise InvalidStateException()
        await self.delete(state)
        return state

    @abc.abstractmethod
    async def get_by_token_identifier(
        self, token_identifier: str
    ) -> WebAuthnState | None:
        """Look up state, including expired state.

        Abstract: Implementation contract
            Match the token identifier exactly. Protect the row before reading and
            retain protection until the transaction ends. Leave commit and rollback to the caller.
        """
        ...

    @abc.abstractmethod
    async def insert(self, state: WebAuthnState) -> typing.Any:
        """Insert state and return its ID.

        Abstract: Implementation contract
            Enforce uniqueness of the token identifier. Raise TokenIdentifierCollision
            on identifier conflict and keep the transaction usable for retry.
            Leave commit and rollback to the caller.
        """
        ...

    @abc.abstractmethod
    async def delete(self, state: WebAuthnState) -> None:
        """Consume the protected state.

        Abstract: Implementation contract
            Delete the supplied row by ID in the transaction protecting it. Concurrent
            finishes must not both succeed. Leave commit and rollback to the caller.
        """
        ...
