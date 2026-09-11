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
        expires_at: The access token expiration as a Unix timestamp in seconds.
        identity_id: The ID of the authenticated identity.
        amr: The authentication methods used to authenticate the identity.
        context: Optional additional data stored with the session.
        refresh_token_hash: The refresh token hash, or None if renewal is disabled.
        refresh_token_expires_at: The family's absolute deadline, or None if this
            session has no refresh token. Replacements inherit the deadline.
        family_id: The initial session's ID, or None before initial insertion.
        replaced_by_id: The replacement session's ID, or None if not replaced.
        revoked_at: The revocation timestamp, or None if not revoked.
    """

    id: typing.Any | None
    token_hash: TokenHash
    expires_at: int
    identity_id: typing.Any
    amr: list[AuthenticationMethodReference]
    context: dict[str, typing.Any] | None = None
    refresh_token_hash: TokenHash | None = None
    refresh_token_expires_at: int | None = None
    family_id: typing.Any | None = None
    replaced_by_id: typing.Any | None = None
    revoked_at: int | None = None

    def is_expired(self) -> bool:
        """
        Check if the access token has expired.

        Returns:
            True if the current time is at or past expiration, False otherwise.
        """
        return get_current_timestamp() >= self.expires_at


class IdentitySessionException(ReauthException):
    """Base exception for identity session errors."""


class InvalidSessionTokenException(IdentitySessionException):
    """Raised when an access token is unknown, malformed, revoked, or replaced."""


class ExpiredSessionException(IdentitySessionException):
    """Raised when an access token has expired."""


class InvalidRefreshTokenException(IdentitySessionException):
    """Raised when a refresh token is unknown, malformed, disabled, or revoked."""


class ExpiredRefreshTokenException(IdentitySessionException):
    """Raised when a refresh token's absolute deadline has passed."""


class ReusedRefreshTokenException(IdentitySessionException):
    """Raised after revoking a family because a consumed refresh token was reused."""


class IdentitySessionService(abc.ABC):
    """
    Abstract base class for managing identity sessions and optional refresh tokens.

    Implementers provide token lookups, initial insertion, atomic replacement,
    and family revocation. Retain replaced sessions until the family's absolute
    deadline so their hashes can identify refresh token reuse.
    """

    def __init__(
        self,
        *,
        hash_secret: str,
        token_prefix: str = "reauth_is_",
        lifetime: datetime.timedelta = datetime.timedelta(hours=24),
        refresh_token_prefix: str = "reauth_isr_",
        refresh_token_lifetime: datetime.timedelta = datetime.timedelta(days=30),
    ) -> None:
        """
        Initialize the identity session service.

        Args:
            hash_secret: The ASCII secret used to compute token hashes.
            token_prefix: The session token prefix. Defaults to "reauth_is_".
            lifetime: The access token lifetime. Defaults to 24 hours.
            refresh_token_prefix: The refresh token prefix. Defaults to "reauth_isr_".
            refresh_token_lifetime: The absolute lifetime of a refreshable family,
                measured from initial issuance. Defaults to 30 days.
        """
        self.hash_secret = hash_secret
        self.token_prefix = token_prefix
        self.lifetime = lifetime
        self.refresh_token_prefix = refresh_token_prefix
        self.refresh_token_lifetime = refresh_token_lifetime

    async def issue(
        self,
        identity_id: typing.Any,
        *,
        amr: list[AuthenticationMethodReference],
        refresh_token: bool = False,
        **context: typing.Any,
    ) -> tuple[str, str | None, IdentitySession]:
        """
        Issue and persist a session for an authenticated identity.

        The caller is responsible for authenticating the identity before issuance.
        Only token hashes are persisted; plaintext tokens are returned to the caller.

        Args:
            identity_id: The ID of the authenticated identity.
            amr: The authentication methods used to authenticate the identity.
            refresh_token: Whether to issue a refresh token. Defaults to False.
            **context: Optional additional data to store with the session.

        Returns:
            A tuple of (token, refresh_token, IdentitySession instance). The
            refresh token is None when renewal is disabled.
        """
        logger.debug("Identity session issuance attempted")
        token, refresh_token_value, identity_session = self._create_session(
            identity_id, amr=amr, context=context or None, refresh_token=refresh_token
        )
        identity_session.id = await self.insert(identity_session)
        identity_session.family_id = identity_session.id
        logger.info(
            "Identity session issued",
            extra={
                "session_id": identity_session.id,
                "expires_at": identity_session.expires_at,
            },
        )
        return token, refresh_token_value, identity_session

    async def validate(self, token: str) -> IdentitySession:
        """
        Validate an access token and return its identity session.

        Args:
            token: The access token to validate.

        Returns:
            The corresponding IdentitySession instance.

        Raises:
            InvalidSessionTokenException: If the token is malformed, unknown,
                revoked, or belongs to a replaced session.
            ExpiredSessionException: If the access token has expired.
        """
        logger.debug("Identity session validation attempted")
        try:
            token_hash = get_token_hash(token, secret=self.hash_secret)
        except UnicodeEncodeError:
            logger.warning("Invalid identity session token provided")
            raise InvalidSessionTokenException() from None

        identity_session = await self.get_by_token_hash(token_hash)
        if (
            identity_session is None
            or identity_session.revoked_at is not None
            or identity_session.replaced_by_id is not None
        ):
            logger.warning("Invalid identity session token provided")
            raise InvalidSessionTokenException()
        if identity_session.is_expired():
            logger.warning(
                "Identity session expired", extra={"session_id": identity_session.id}
            )
            raise ExpiredSessionException()
        return identity_session

    async def refresh(
        self, token: str, *, refresh_token: bool = True
    ) -> tuple[str, str | None, IdentitySession]:
        """
        Consume a refresh token and atomically replace its session.

        Both previous tokens become invalid. The replacement retains the identity,
        AMR, context, family, and absolute deadline, even if access has expired.
        Reuse of a consumed refresh token revokes its whole family.

        Args:
            token: The refresh token to consume.
            refresh_token: Whether to issue another refresh token. Defaults to True.
                False issues a final session whose expiry is still capped by the
                family's deadline, with no further renewal capability.

        Returns:
            A tuple of (token, refresh_token, IdentitySession instance). The
            refresh token is None when renewal is disabled.

        Raises:
            InvalidRefreshTokenException: If the token is malformed, unknown,
                revoked, or otherwise no longer refreshable.
            ExpiredRefreshTokenException: If the absolute deadline has passed.
            ReusedRefreshTokenException: If the token was already consumed.
                Family revocation is persisted before this exception is raised.
        """  # noqa: DOC502
        logger.debug("Identity session refresh attempted")
        try:
            token_hash = get_token_hash(token, secret=self.hash_secret)
        except UnicodeEncodeError:
            logger.warning("Invalid refresh token provided")
            raise InvalidRefreshTokenException() from None

        previous_session = await self._validate_refresh_token_hash(token_hash)
        token_value, refresh_token_value, new_session = self._create_session(
            previous_session.identity_id,
            amr=previous_session.amr,
            context=previous_session.context,
            refresh_token=refresh_token,
            refresh_token_expires_at=previous_session.refresh_token_expires_at,
            family_id=previous_session.family_id,
        )
        new_session.id = await self.replace(previous_session, new_session)
        if new_session.id is None:
            await self._validate_refresh_token_hash(token_hash)
            logger.warning("Identity session replacement rejected")
            raise InvalidRefreshTokenException()
        logger.info(
            "Identity session refreshed",
            extra={"session_id": new_session.id, "family_id": new_session.family_id},
        )
        return token_value, refresh_token_value, new_session

    async def revoke(self, token: str) -> None:
        """
        Revoke an entire family identified by an access or refresh token.

        Expired and replaced tokens can still identify a family. Unknown,
        malformed, and already-revoked tokens succeed without error.

        Args:
            token: An access token or refresh token from the family to revoke.
        """
        logger.debug("Identity session revocation attempted")
        try:
            token_hash = get_token_hash(token, secret=self.hash_secret)
        except UnicodeEncodeError:
            return
        identity_session = await self.get_by_token_hash(token_hash)
        if identity_session is None:
            identity_session = await self.get_by_refresh_token_hash(token_hash)
        if identity_session is None:
            return
        identity_session.revoked_at = get_current_timestamp()
        await self.revoke_family(identity_session)
        logger.info(
            "Identity session family revoked",
            extra={"family_id": identity_session.family_id},
        )

    def _create_session(
        self,
        identity_id: typing.Any,
        *,
        amr: list[AuthenticationMethodReference],
        context: dict[str, typing.Any] | None,
        refresh_token: bool,
        refresh_token_expires_at: int | None = None,
        family_id: typing.Any | None = None,
    ) -> tuple[str, str | None, IdentitySession]:
        """
        Generate credentials and a session model without persisting it.

        Args:
            identity_id: The authenticated identity's ID.
            amr: The authentication methods to retain.
            context: Additional data to retain.
            refresh_token: Whether to generate a refresh token.
            refresh_token_expires_at: The inherited deadline, or None for issuance.
            family_id: The existing family ID, or None for issuance.

        Returns:
            A tuple of (token, optional refresh token, unsaved session).
        """
        now = get_current_timestamp()
        token, token_hash = generate_token_hash_pair(
            secret=self.hash_secret, prefix=self.token_prefix
        )
        refresh_token_value = None
        refresh_token_hash = None
        if refresh_token:
            refresh_token_value, refresh_token_hash = generate_token_hash_pair(
                secret=self.hash_secret, prefix=self.refresh_token_prefix
            )
            if refresh_token_expires_at is None:
                refresh_token_expires_at = now + int(
                    self.refresh_token_lifetime.total_seconds()
                )
        expires_at = now + int(self.lifetime.total_seconds())
        if refresh_token_expires_at is not None:
            expires_at = min(expires_at, refresh_token_expires_at)
        return (
            token,
            refresh_token_value,
            IdentitySession(
                id=None,
                token_hash=token_hash,
                expires_at=expires_at,
                identity_id=identity_id,
                amr=amr.copy(),
                context=context.copy() if context else None,
                refresh_token_hash=refresh_token_hash,
                refresh_token_expires_at=refresh_token_expires_at
                if refresh_token
                else None,
                family_id=family_id,
            ),
        )

    async def _validate_refresh_token_hash(
        self, token_hash: TokenHash
    ) -> IdentitySession:
        """
        Load a refresh token's session, revoking its family on reuse.

        Args:
            token_hash: The refresh token hash to look up.

        Returns:
            The session eligible for replacement.

        Raises:
            InvalidRefreshTokenException: If the token is unknown, disabled, or revoked.
            ExpiredRefreshTokenException: If the absolute deadline has passed.
            ReusedRefreshTokenException: If the token was consumed previously.
        """
        identity_session = await self.get_by_refresh_token_hash(token_hash)
        if identity_session is None or identity_session.revoked_at is not None:
            logger.warning("Invalid refresh token provided")
            raise InvalidRefreshTokenException()
        if identity_session.replaced_by_id is not None:
            identity_session.revoked_at = get_current_timestamp()
            await self.revoke_family(identity_session)
            logger.warning(
                "Refresh token reused; family revoked",
                extra={"family_id": identity_session.family_id},
            )
            raise ReusedRefreshTokenException()
        if identity_session.refresh_token_expires_at is None:
            logger.warning("Session has no refresh deadline")
            raise InvalidRefreshTokenException()
        if get_current_timestamp() >= identity_session.refresh_token_expires_at:
            logger.warning(
                "Refresh token expired", extra={"session_id": identity_session.id}
            )
            raise ExpiredRefreshTokenException()
        return identity_session

    @abc.abstractmethod
    async def insert(self, identity_session: IdentitySession) -> typing.Any:
        """
        Atomically insert a session and initialize its family ID.

        If family_id is None, set the stored family_id to the generated record ID
        in the same transaction. Preserve an explicitly supplied family ID.

        Args:
            identity_session: The complete session model to insert.

        Returns:
            The ID of the inserted session.
        """
        ...

    @abc.abstractmethod
    async def get_by_token_hash(self, token_hash: TokenHash) -> IdentitySession | None:
        """
        Retrieve a session by its access token hash, regardless of its validity.

        Args:
            token_hash: The access token hash to look up.

        Returns:
            The stored session, including expired, replaced, or revoked rows,
            or None if not found.
        """
        ...

    @abc.abstractmethod
    async def get_by_refresh_token_hash(
        self, refresh_token_hash: TokenHash
    ) -> IdentitySession | None:
        """
        Retrieve a session by its refresh token hash, regardless of its validity.

        Args:
            refresh_token_hash: The refresh token hash to look up.

        Returns:
            The stored session, including expired, replaced, or revoked rows,
            or None if not found.
        """
        ...

    @abc.abstractmethod
    async def replace(
        self, previous_session: IdentitySession, new_session: IdentitySession
    ) -> typing.Any | None:
        """
        Atomically replace a session if its refresh token is still usable.

        Serialize with all replacements and revocations in the same family,
        for example by locking the retained initial session row. Reload the
        previous session under that lock: its refresh hash must still match,
        its refresh deadline must be in the future, and it must be neither
        revoked nor replaced. Also reject a revoked or missing family root.

        Insert new_session with the same family ID and set the previous row's
        replaced_by_id to the new ID. Commit both changes before returning;
        roll back both on failure. Do not call the public issue() method.

        Args:
            previous_session: The previously retrieved session to replace.
            new_session: The complete replacement model to persist.

        Returns:
            The replacement ID, or None with no changes if the previous session
            is no longer eligible. Propagate storage failures after rollback.
        """
        ...

    @abc.abstractmethod
    async def revoke_family(self, identity_session: IdentitySession) -> None:
        """
        Persist revocation of every session in the supplied session's family.

        Use identity_session.revoked_at, set by the service, for rows not yet
        revoked. Preserve earlier revocation timestamps, hashes, and lineage.
        Serialize with replace() through the same family lock and commit before
        returning. A caller's subsequent exception must not undo revocation.
        Missing or already-revoked families succeed without error.

        Args:
            identity_session: The session identifying the family and revocation time.
        """
        ...
