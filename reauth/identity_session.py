import abc
import dataclasses
import datetime
import typing

from reauth.amr import AuthenticationMethodReference
from reauth.crypto import TokenHash, generate_token_hash_pair, get_token_hash
from reauth.exceptions import ReauthException
from reauth.logging import get_logger
from reauth.timestamp import get_current_timestamp

logger = get_logger(__name__)


@dataclasses.dataclass
class IdentitySession:
    """
    The authenticated state of an identity, accessed through a session token.

    Attributes:
        id: The stored session ID, or None before insertion.
        token_hash: The HMAC-SHA256 hash of the session token.
        expires_at: The expiration time as a Unix timestamp in seconds.
        identity_id: The ID of the authenticated identity.
        amr: The authentication methods used to authenticate the identity.
        context: Optional additional data stored with the session.
    """

    id: typing.Any | None
    token_hash: TokenHash
    expires_at: int
    identity_id: typing.Any
    amr: list[AuthenticationMethodReference]
    context: dict[str, typing.Any] | None = None

    def is_expired(self) -> bool:
        """
        Check if the session has expired.

        Returns:
            True if the current time is at or past expiration, False otherwise.
        """
        return get_current_timestamp() >= self.expires_at


class IdentitySessionException(ReauthException):
    """Base exception for identity session errors."""


class InvalidSessionTokenException(IdentitySessionException):
    """Raised when a token is invalid or does not correspond to any session."""


class ExpiredSessionException(IdentitySessionException):
    """Raised when a session has expired."""


class IdentitySessionService(abc.ABC):
    """
    Abstract base class for managing identity sessions.

    An identity session represents an authenticated identity. Its token can be
    passed through a cookie or used as an API token. Implementers provide the
    persistence methods for storing, retrieving, and deleting sessions.
    """

    def __init__(
        self,
        *,
        hash_secret: str,
        token_prefix: str = "reauth_is_",
        lifetime: datetime.timedelta = datetime.timedelta(hours=24),
    ) -> None:
        """
        Initialize the identity session service.

        Args:
            hash_secret: The ASCII secret used to compute session token hashes.
            token_prefix: The prefix prepended to generated session tokens.
                Defaults to "reauth_is_".
            lifetime: The duration for which issued sessions are valid.
                Defaults to 24 hours.
        """
        self.hash_secret = hash_secret
        self.token_prefix = token_prefix
        self.lifetime = lifetime

    async def issue(
        self,
        identity_id: typing.Any,
        *,
        amr: list[AuthenticationMethodReference],
        **context: typing.Any,
    ) -> tuple[str, IdentitySession]:
        """
        Issue and persist a session for an authenticated identity.

        The caller is responsible for authenticating the identity before issuance.
        Only the token hash is persisted; the plaintext token is returned to the caller.

        Args:
            identity_id: The ID of the authenticated identity.
            amr: The authentication methods used to authenticate the identity.
            **context: Optional keyword arguments for additional data to store with
                the session (e.g., device="laptop").

        Returns:
            A tuple of (token, IdentitySession instance).
        """
        logger.debug("Identity session issuance attempted")
        token, token_hash = generate_token_hash_pair(
            secret=self.hash_secret, prefix=self.token_prefix
        )
        identity_session = IdentitySession(
            id=None,
            token_hash=token_hash,
            expires_at=get_current_timestamp() + int(self.lifetime.total_seconds()),
            identity_id=identity_id,
            amr=amr,
            context=context or None,
        )
        identity_session.id = await self.insert(identity_session)
        logger.info(
            "Identity session issued",
            extra={
                "session_id": identity_session.id,
                "expires_at": identity_session.expires_at,
            },
        )
        return token, identity_session

    async def validate(self, token: str) -> IdentitySession:
        """
        Validate a token and return the corresponding identity session.

        Args:
            token: The token to validate.

        Returns:
            The corresponding IdentitySession instance.

        Raises:
            InvalidSessionTokenException: If the token contains non-ASCII characters
                or does not correspond to any stored session.
            ExpiredSessionException: If the session corresponding to the token has expired.
        """
        logger.debug("Identity session validation attempted")
        try:
            token_hash = get_token_hash(token, secret=self.hash_secret)
        except UnicodeEncodeError:
            logger.warning("Invalid identity session token provided")
            raise InvalidSessionTokenException() from None

        identity_session = await self.get_by_token_hash(token_hash)
        if identity_session is None:
            logger.warning("Invalid identity session token provided")
            raise InvalidSessionTokenException()
        if identity_session.is_expired():
            logger.warning(
                "Identity session expired", extra={"session_id": identity_session.id}
            )
            raise ExpiredSessionException()
        return identity_session

    async def revoke(self, identity_session: IdentitySession) -> None:
        """
        Revoke an identity session by deleting it from the persistent store.

        Subsequent token validation fails. Revoking an already-deleted session
        succeeds without error.

        Args:
            identity_session: The IdentitySession instance to revoke.
        """
        logger.debug(
            "Identity session revocation attempted",
            extra={"session_id": identity_session.id},
        )
        await self.delete(identity_session)
        logger.info(
            "Identity session revoked", extra={"session_id": identity_session.id}
        )

    @abc.abstractmethod
    async def insert(self, identity_session: IdentitySession) -> typing.Any:
        """
        Insert an identity session into a persistent store.

        Implementers should implement this method.

        Args:
            identity_session: The IdentitySession instance to insert.

        Returns:
            The ID of the inserted identity session.
        """
        ...

    @abc.abstractmethod
    async def get_by_token_hash(self, token_hash: TokenHash) -> IdentitySession | None:
        """
        Retrieve an identity session by its token hash from the persistent store.

        Implementers should implement this method. Expiration is checked by validate().

        Args:
            token_hash: The hash of the token to look up.

        Returns:
            The corresponding IdentitySession instance, or None if not found.
        """
        ...

    @abc.abstractmethod
    async def delete(self, identity_session: IdentitySession) -> None:
        """
        Delete an identity session from the persistent store.

        Implementers should implement this method. Deleting an already-deleted
        session must succeed without error.

        Args:
            identity_session: The IdentitySession instance to delete.
        """
        ...
