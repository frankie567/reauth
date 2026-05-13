import abc
import dataclasses
import datetime
import typing

from .amr import AuthenticationMethodReference
from .crypto import TokenHash, generate_token_hash_pair, get_token_hash
from .exceptions import ReauthException
from .factors import FactorBase
from .timestamp import get_current_timestamp


@dataclasses.dataclass
class AuthenticationSession:
    id: typing.Any | None
    token_hash: TokenHash
    expires_at: int
    identity_id: typing.Any | None
    amr: list[AuthenticationMethodReference] = dataclasses.field(default_factory=list)
    used_factors: list[str] = dataclasses.field(default_factory=list)

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


class UnavailableFactorException(AuthenticationSessionException):
    """Raised when trying to advance a session with a factor that is not available for the session."""

    pass


class IdentityNotAttachedException(AuthenticationSessionException):
    """Raised when trying to complete a session without an identity_id."""

    pass


class FactorsRemainingException(AuthenticationSessionException):
    """
    Raised when trying to complete a session with remaining factors.

    Attributes:
        factors: A set of the remaining factors instances.
    """

    def __init__(self, factors: set[FactorBase[typing.Any]]) -> None:
        self.factors = factors
        super().__init__("Cannot complete session: factors are remaining")


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
        factors: set[FactorBase[typing.Any]],
        token_prefix: str = "ls_",
        lifetime: datetime.timedelta = datetime.timedelta(minutes=15),
    ) -> None:
        self.hash_secret = hash_secret
        self.factors = factors
        self.token_prefix = token_prefix
        self.lifetime = lifetime

    async def create(self) -> tuple[str, AuthenticationSession]:
        """
        Create a fresh authentication session.

        Returns:
            A tuple of (token, AuthenticationSession instance).
        """
        token, token_hash = generate_token_hash_pair(
            secret=self.hash_secret, prefix=self.token_prefix
        )
        authentication_session = AuthenticationSession(
            id=None,
            token_hash=token_hash,
            expires_at=get_current_timestamp() + int(self.lifetime.total_seconds()),
            identity_id=None,
        )
        authentication_session.id = await self.insert(authentication_session)
        return token, authentication_session

    async def get_by_token(self, token: str) -> AuthenticationSession:
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

    async def get_available_factors(
        self, authentication_session: AuthenticationSession
    ) -> set[FactorBase[typing.Any]]:
        """
        Get the set of available factors for a given authentication session.

        Args:
            authentication_session: The AuthenticationSession instance to get available factors for.

        Returns:
            A set of FactorBase instances representing the available factors for the session.
        """
        available: set[FactorBase[typing.Any]] = set()
        for factor in self.factors:
            # Already used?
            if factor.AMR in authentication_session.amr:
                continue
            # Meets min_prior_factors?
            if len(authentication_session.amr) < factor.min_prior_factors:
                continue
            # Enrolled for the identity in the session (if any)?
            if authentication_session.identity_id is not None:
                factor_enrollment = await factor.get_enrollment(
                    authentication_session.identity_id
                )
                if factor_enrollment is None:
                    continue
            available.add(factor)
        return available

    async def advance(
        self,
        authentication_session: AuthenticationSession,
        identity_id: typing.Any,
        factor: FactorBase[typing.Any],
    ) -> AuthenticationSession:
        """
        Advance an authentication session by marking a factor as completed.

        Args:
            authentication_session: The AuthenticationSession instance to advance.
            identity_id: The ID of the identity that has completed the factor.
            factor: The FactorBase instance representing the factor that has been completed.

        Returns:
            The updated AuthenticationSession instance.

        Raises:
            UnavailableFactorException: If the factor is not available for the session.
        """
        available_factors = await self.get_available_factors(authentication_session)
        if factor not in available_factors:
            raise UnavailableFactorException()

        authentication_session.identity_id = identity_id
        authentication_session.amr.append(factor.AMR)
        authentication_session.used_factors.append(factor.identifier)
        await self.update(authentication_session)

        return authentication_session

    async def complete(
        self, authentication_session: AuthenticationSession
    ) -> tuple[typing.Any, list[AuthenticationMethodReference]]:
        """
        Complete an authentication session and return identity info.

        Validates that the session is complete (identity attached, no factors remaining),
        deletes the session, and returns the identity_id and AMR list.

        Args:
            authentication_session: The session to complete.

        Returns:
            A tuple of (identity_id, amr) for creating a user session.

        Raises:
            IdentityNotAttachedException: If no identity_id is attached to the session.
            FactorsRemainingException: If there are still available factors.
        """
        if authentication_session.identity_id is None:
            raise IdentityNotAttachedException()

        available_factors = await self.get_available_factors(authentication_session)
        if available_factors:
            raise FactorsRemainingException(available_factors)

        await self.delete(authentication_session)
        return authentication_session.identity_id, authentication_session.amr

    @abc.abstractmethod
    async def insert(self, authentication_session: AuthenticationSession) -> typing.Any:
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
    async def get_by_token_hash(self, token_hash: str) -> AuthenticationSession | None:
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
    async def update(self, authentication_session: AuthenticationSession) -> None:
        """
        Update an authentication session in the persistent store.

        Implementers should implement this method.

        Args:
            authentication_session: The AuthenticationSession instance to update.
        """
        ...

    @abc.abstractmethod
    async def delete(self, authentication_session: AuthenticationSession) -> None:
        """
        Delete an authentication session from the persistent store.

        Implementers should implement this method.

        Args:
            authentication_session: The AuthenticationSession instance to delete.
        """
        ...
