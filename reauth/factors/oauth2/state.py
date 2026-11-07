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


@dataclasses.dataclass
class OAuth2State:
    id: typing.Any | None
    token_identifier: str
    token_verifier: str
    provider: str
    code_verifier: str | None
    nonce: str | None
    redirect_uri: str
    identity_id: typing.Any | None
    scope: list[str] | None
    expires_at: int
    context: dict[str, typing.Any] | None = None


class OAuth2StateException(ReauthException):
    """Base exception for OAuth2 state errors."""


class InvalidStateException(OAuth2StateException):
    """Raised when a state token is invalid or does not correspond to any state."""


class ExpiredStateException(OAuth2StateException):
    """Raised when a state has expired."""


class OAuth2StateService(abc.ABC):
    """
    Service for managing OAuth2 state data storage.

    Pure CRUD operations - no business logic. The factor handles flow validation.
    """

    def __init__(
        self,
        *,
        token_provider: TokenProvider,
        lifetime: datetime.timedelta = datetime.timedelta(minutes=10),
    ) -> None:
        self.token_provider = token_provider
        self.lifetime = lifetime

    async def create(
        self,
        *,
        provider: str,
        redirect_uri: str,
        identity_id: typing.Any | None = None,
        nonce: str | None = None,
        code_verifier: str | None = None,
        scope: list[str] | None = None,
        **context: typing.Any,
    ) -> tuple[str, OAuth2State]:
        """
        Create a new OAuth2 state and store it.

        Returns:
            A tuple of (state_token, OAuth2State).
            The caller MUST bind state_token to the user agent context.

        Raises:
            TokenGenerationException: If credential generation repeatedly collides.
        """
        logger.debug("OAuth2 state creation attempted", extra={"provider": provider})
        generated = await self.token_provider.generate()
        oauth2_state = OAuth2State(
            id=None,
            token_identifier=generated.identifier,
            token_verifier=generated.verifier,
            provider=provider,
            code_verifier=code_verifier,
            nonce=nonce,
            redirect_uri=redirect_uri,
            identity_id=identity_id,
            scope=scope,
            expires_at=get_current_timestamp() + int(self.lifetime.total_seconds()),
            context=context or None,
        )
        for attempt in range(3):
            try:
                oauth2_state.id = await self.insert(oauth2_state)
                break
            except TokenIdentifierCollision as error:
                if attempt == 2:
                    raise TokenGenerationException() from error
                generated = await self.token_provider.generate()
                oauth2_state.token_identifier = generated.identifier
                oauth2_state.token_verifier = generated.verifier
        logger.info(
            "OAuth2 state created",
            extra={
                "state_id": oauth2_state.id,
                "provider": provider,
                "expires_at": oauth2_state.expires_at,
            },
        )
        return generated.token, oauth2_state

    async def consume(self, state: str) -> OAuth2State:
        """
        Atomically retrieve and delete an OAuth2 state.

        Args:
            state: The state token to consume.

        Returns:
            The corresponding OAuth2State instance.

        Raises:
            InvalidStateException: If the state is invalid or does not correspond to any state.
            ExpiredStateException: If the state has expired.
        """
        logger.debug("OAuth2 state consumption attempted")
        try:
            parts = self.token_provider.parse(state)
        except InvalidTokenException:
            logger.warning("Malformed token provided")
            raise InvalidStateException() from None
        oauth2_state = await self.get_by_token_identifier(parts.identifier)

        if oauth2_state is None:
            logger.warning("Invalid OAuth2 state provided for consumption")
            raise InvalidStateException()

        valid, _ = await self.token_provider.verify_and_update(
            parts.secret, oauth2_state.token_verifier
        )
        if not valid:
            logger.warning("Invalid token secret provided")
            raise InvalidStateException()
        if oauth2_state.expires_at <= get_current_timestamp():
            logger.warning(
                "OAuth2 state expired",
                extra={"state_id": oauth2_state.id},
            )
            raise ExpiredStateException()

        await self.delete(oauth2_state)
        logger.info(
            "OAuth2 state consumed",
            extra={
                "state_id": oauth2_state.id,
                "provider": oauth2_state.provider,
            },
        )
        return oauth2_state

    @abc.abstractmethod
    async def get_by_token_identifier(
        self, token_identifier: str
    ) -> OAuth2State | None:
        """
        Retrieve OAuth2 state by its identifier from persistent store.

        Args:
            token_identifier: The identifier of the state token to look up.

        Returns:
            The corresponding OAuth2State instance, or None if not found.
        """
        ...

    @abc.abstractmethod
    async def insert(self, oauth2_state: OAuth2State) -> typing.Any:
        """
        Insert OAuth2 state into persistent store.

        Args:
            oauth2_state: The OAuth2State instance to insert.

        Returns:
            The ID of the inserted OAuth2State.

        Raises:
            TokenIdentifierCollision: If the identifier already exists in the store.
        """
        ...

    @abc.abstractmethod
    async def delete(self, oauth2_state: OAuth2State) -> None:
        """
        Delete OAuth2 state from persistent store.

        Args:
            oauth2_state: The OAuth2State instance to delete.
        """
        ...
