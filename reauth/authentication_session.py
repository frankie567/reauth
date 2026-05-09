import abc
import dataclasses
import datetime

from .crypto import TokenHash, generate_token_hash_pair, get_token_hash
from .exceptions import ReauthException
from .timestamp import get_current_timestamp


@dataclasses.dataclass
class AuthenticationSession[IDType]:
    id: IDType | None
    token_hash: TokenHash
    expires_at: int
    identity_id: IDType | None

    def is_expired(self) -> bool:
        """
        Check if the session has expired.

        Returns:
            True if the session has expired, False otherwise.
        """
        return get_current_timestamp() >= self.expires_at


class AuthenticationSessionException(ReauthException):
    """Base exception for authentication session errors."""

    pass


class InvalidSessionTokenException(AuthenticationSessionException):
    """Raised when a token is invalid or does not correspond to any session."""

    pass


class ExpiredSessionException(AuthenticationSessionException):
    """Raised when a session has expired."""

    pass


class AuthenticationSessionService(abc.ABC):
    """
    Abstract base class for managing authentication sessions.

    An authentication session represents a pre-auth state that can be used to
    authenticate a user, allowing to manage multi-factor authentication flows.
    """

    def __init__(
        self,
        *,
        hash_secret: str,
        token_prefix: str = "ls_",
        lifetime: datetime.timedelta = datetime.timedelta(minutes=15),
    ) -> None:
        self.hash_secret = hash_secret
        self.token_prefix = token_prefix
        self.lifetime = lifetime

    async def create(self) -> tuple[str, AuthenticationSession[object]]:
        """
        Create a fresh authentication session.

        Returns:
            A tuple of (token, AuthenticationSession instance).
        """
        token, token_hash = generate_token_hash_pair(
            secret=self.hash_secret, prefix=self.token_prefix
        )
        authentication_session = AuthenticationSession[object](
            id=None,
            token_hash=token_hash,
            expires_at=get_current_timestamp() + int(self.lifetime.total_seconds()),
            identity_id=None,
        )
        authentication_session.id = await self.insert(authentication_session)
        return token, authentication_session

    async def get_by_token(self, token: str) -> AuthenticationSession[object]:
        """
        Validate a token and return the corresponding authentication session.

        Args:
            token: The token to validate.

        Returns:
            The corresponding AuthenticationSession instance.

        Raises:
            InvalidTokenException: If the token is invalid or does not correspond to any session.
            ExpiredSessionException: If the session corresponding to the token has expired.
        """
        token_hash = get_token_hash(token, secret=self.hash_secret)
        authentication_session = await self.get_by_token_hash(token_hash)
        if authentication_session is None:
            raise InvalidSessionTokenException()
        if authentication_session.is_expired():
            raise ExpiredSessionException()
        return authentication_session

    @abc.abstractmethod
    async def insert[IDType](
        self, authentication_session: AuthenticationSession[IDType]
    ) -> IDType:
        """
        Insert an authentication session into a persistent store.

        Implementers should implement this method.

        Args:
            authentication_session: The AuthenticationSession instance to insert.

        Returns:
            The ID of the inserted authentication session.
        """
        ...

    @abc.abstractmethod
    async def get_by_token_hash(
        self, token_hash: str
    ) -> AuthenticationSession[object] | None:
        """
        Retrieve an authentication session by its token hash from the persistent store.

        Implementers should implement this method.

        Args:
            token_hash: The hash of the token to look up.

        Returns:
            The corresponding AuthenticationSession instance, or None if not found.
        """
        ...

    @abc.abstractmethod
    async def update[IDType](
        self, authentication_session: AuthenticationSession[IDType]
    ) -> None:
        """
        Update an authentication session in the persistent store.

        Implementers should implement this method.

        Args:
            authentication_session: The AuthenticationSession instance to update.
        """
        ...
