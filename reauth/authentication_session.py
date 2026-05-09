import dataclasses
import datetime
from abc import ABC, abstractmethod

from .crypto import generate_token_hash_pair, get_token_hash
from .exceptions import ReauthException


@dataclasses.dataclass
class AuthenticationSession[IDType]:
    id: IDType | None
    token_hash: str
    expires_at: int
    identity_id: IDType | None

    def is_expired(self) -> bool:
        """
        Check if the session has expired.

        Returns:
            True if the session has expired, False otherwise.
        """
        now = datetime.datetime.now(datetime.UTC).timestamp()
        return now >= self.expires_at


class AuthenticationSessionException(ReauthException):
    """Base exception for authentication session errors."""

    pass


class InvalidSessionTokenException(AuthenticationSessionException):
    """Raised when a token is invalid or does not correspond to any session."""

    pass


class ExpiredSessionException(AuthenticationSessionException):
    """Raised when a session has expired."""

    pass


class AuthenticationSessionService(ABC):
    """
    Abstract base class for managing authentication sessions.

    An authentication session represents a pre-auth state that can be used to
    authenticate a user, allowing to manage multi-factor authentication flows.
    """

    def __init__(
        self,
        *,
        token_secret: str,
        token_prefix: str = "ls_",
        lifetime: datetime.timedelta = datetime.timedelta(minutes=15),
    ) -> None:
        self.token_secret = token_secret
        self.token_prefix = token_prefix
        self.lifetime = lifetime

    async def create(self) -> tuple[str, AuthenticationSession[object]]:
        """
        Create a fresh authentication session.

        Returns:
            A tuple of (token, AuthenticationSession instance).
        """
        token, token_hash = generate_token_hash_pair(
            secret=self.token_secret, prefix=self.token_prefix
        )
        now = datetime.datetime.now(datetime.UTC).timestamp()
        authentication_session = AuthenticationSession[object](
            id=None,
            token_hash=token_hash,
            expires_at=int(now + self.lifetime.total_seconds()),
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
        token_hash = get_token_hash(token, secret=self.token_secret)
        authentication_session = await self.get_by_token_hash(token_hash)
        if authentication_session is None:
            raise InvalidSessionTokenException()
        if authentication_session.is_expired():
            raise ExpiredSessionException()
        return authentication_session

    @abstractmethod
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

    @abstractmethod
    async def get_by_token_hash(
        self, token_hash: str
    ) -> AuthenticationSession[object] | None:
        """
        Retrieve an authentication session by its token hash.

        Implementers should implement this method.

        Args:
            token_hash: The hash of the token to look up.

        Returns:
            The corresponding AuthenticationSession instance, or None if not found.
        """
        ...

    @abstractmethod
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
