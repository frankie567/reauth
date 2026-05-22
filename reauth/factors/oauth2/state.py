import abc
import dataclasses
import datetime
import typing

from reauth.crypto import TokenHash, generate_token_hash_pair, get_token_hash
from reauth.exceptions import ReauthException
from reauth.logging import get_logger
from reauth.timestamp import get_current_timestamp

logger = get_logger(__name__)


@dataclasses.dataclass
class OAuth2State:
    id: typing.Any | None
    state_hash: TokenHash
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
        hash_secret: str,
        lifetime: datetime.timedelta = datetime.timedelta(minutes=10),
        token_prefix: str = "reauth_oauth2_",
    ) -> None:
        self.hash_secret = hash_secret
        self.lifetime = lifetime
        self.token_prefix = token_prefix

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
        """
        logger.debug("OAuth2 state creation attempted", extra={"provider": provider})
        token, token_hash = generate_token_hash_pair(
            secret=self.hash_secret, prefix=self.token_prefix
        )
        oauth2_state = OAuth2State(
            id=None,
            state_hash=token_hash,
            provider=provider,
            code_verifier=code_verifier,
            nonce=nonce,
            redirect_uri=redirect_uri,
            identity_id=identity_id,
            scope=scope,
            expires_at=get_current_timestamp() + int(self.lifetime.total_seconds()),
            context=context or None,
        )
        oauth2_state.id = await self.insert(oauth2_state)
        logger.info(
            "OAuth2 state created",
            extra={
                "state_id": oauth2_state.id,
                "provider": provider,
                "expires_at": oauth2_state.expires_at,
            },
        )
        return token, oauth2_state

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
        state_hash = get_token_hash(state, secret=self.hash_secret)
        oauth2_state = await self.get_by_state_hash(state_hash)

        if oauth2_state is None:
            logger.warning("Invalid OAuth2 state provided for consumption")
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
    async def get_by_state_hash(self, state_hash: TokenHash) -> OAuth2State | None:
        """
        Retrieve OAuth2 state by its hash from persistent store.

        Args:
            state_hash: The hash of the state token to look up.

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
