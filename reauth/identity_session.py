import abc
import dataclasses
import datetime
import typing

from reauth.amr import AuthenticationMethodReference
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
class IdentitySession:
    """
    The authenticated state of an identity, accessed through a session token.

    Attributes:
        id: The stored session ID, or None before insertion.
        token_identifier: The public lookup identifier of the session token.
        token_verifier: The opaque access-token secret verifier.
        expires_at: The access token expiration as a Unix timestamp in seconds.
        identity_id: The ID of the authenticated identity.
        amr: The authentication methods used to authenticate the identity.
        context: Optional additional data stored with the session.
        refresh_token_identifier: The refresh token identifier, or None if renewal is disabled.
        refresh_token_verifier: The opaque refresh verifier, or None if disabled.
        refresh_token_expires_at: The family's absolute deadline, or None if this
            session has no refresh token. Replacements inherit the deadline.
        family_id: The initial session's ID, or None before initial insertion.
        replaced_by_id: The replacement session's ID, or None if not replaced.
        revoked_at: The revocation timestamp, or None if not revoked.
    """

    id: typing.Any | None
    token_identifier: str
    token_verifier: str
    expires_at: int
    identity_id: typing.Any
    amr: list[AuthenticationMethodReference]
    context: dict[str, typing.Any] | None = None
    refresh_token_identifier: str | None = None
    refresh_token_verifier: str | None = None
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
    deadline so their identifiers and verifiers can identify refresh token reuse.
    """

    def __init__(
        self,
        *,
        token_provider: TokenProvider,
        refresh_token_provider: TokenProvider,
        lifetime: datetime.timedelta = datetime.timedelta(hours=24),
        refresh_token_lifetime: datetime.timedelta = datetime.timedelta(days=30),
    ) -> None:
        """
        Initialize the identity session service.

        Args:
            token_provider: Access token generation and verification.
            refresh_token_provider: Independent refresh token generation and verification.
            lifetime: The access token lifetime. Defaults to 24 hours.
            refresh_token_lifetime: The absolute lifetime of a refreshable family,
                measured from initial issuance. Defaults to 30 days.
        """
        self.token_provider = token_provider
        self.refresh_token_provider = refresh_token_provider
        self.lifetime = lifetime
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
        Only token identifiers and verifiers are persisted; plaintext tokens are returned to the caller.

        Args:
            identity_id: The ID of the authenticated identity.
            amr: The authentication methods used to authenticate the identity.
            refresh_token: Whether to issue a refresh token. Defaults to False.
            **context: Optional additional data to store with the session.

        Returns:
            A tuple of (token, refresh_token, IdentitySession instance). The
            refresh token is None when renewal is disabled.

        Raises:
            TokenGenerationException: If credential generation repeatedly collides.
        """
        logger.debug("Identity session issuance attempted")
        for attempt in range(3):
            token, refresh_token_value, identity_session = await self._create_session(
                identity_id,
                amr=amr,
                context=context or None,
                refresh_token=refresh_token,
            )
            try:
                identity_session.id = await self.insert(identity_session)
                break
            except TokenIdentifierCollision as error:
                if attempt == 2:
                    raise TokenGenerationException() from error
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
            parts = self.token_provider.parse(token)
        except InvalidTokenException:
            logger.warning("Invalid identity session token provided")
            raise InvalidSessionTokenException() from None

        identity_session = await self.get_by_token_identifier(parts.identifier)
        if (
            identity_session is None
            or identity_session.revoked_at is not None
            or identity_session.replaced_by_id is not None
        ):
            logger.warning("Invalid identity session token provided")
            raise InvalidSessionTokenException()
        valid, replacement = await self.token_provider.verify_and_update(
            parts.secret, identity_session.token_verifier
        )
        if not valid:
            logger.warning("Invalid identity session secret provided")
            raise InvalidSessionTokenException()
        if identity_session.is_expired():
            logger.warning(
                "Identity session expired", extra={"session_id": identity_session.id}
            )
            raise ExpiredSessionException()
        if replacement is not None:
            identity_session.token_verifier = replacement
            await self.update_verifier(identity_session)
        return identity_session

    async def refresh(
        self, token: str, *, refresh_token: bool = True
    ) -> tuple[str, str | None, IdentitySession]:
        """
        Consume a refresh token and atomically replace its session.

        Both previous tokens become invalid. The replacement retains the identity,
        AMR, context, family, and absolute deadline, even if access has expired.
        Reuse of a consumed refresh token revokes its whole family.

        Commit the caller's transaction before exposing the replacement tokens.
        Catch ReusedRefreshTokenException inside the transaction and commit the
        family revocation before reporting the authentication failure.

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
                Family revocation is pending in the caller's transaction and must
                be committed despite this exception.
            TokenGenerationException: If credential generation repeatedly collides.
        """  # noqa: DOC502
        logger.debug("Identity session refresh attempted")
        previous_session = await self._validate_refresh_token(token)
        for attempt in range(3):
            token_value, refresh_token_value, new_session = await self._create_session(
                previous_session.identity_id,
                amr=previous_session.amr,
                context=previous_session.context,
                refresh_token=refresh_token,
                refresh_token_expires_at=previous_session.refresh_token_expires_at,
                family_id=previous_session.family_id,
            )
            try:
                new_session.id = await self.replace(previous_session, new_session)
                break
            except TokenIdentifierCollision as error:
                if attempt == 2:
                    raise TokenGenerationException() from error
        if new_session.id is None:
            await self._validate_refresh_token(token)
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
        Commit the caller's transaction before reporting successful revocation.

        Args:
            token: An access token or refresh token from the family to revoke.
        """
        logger.debug("Identity session revocation attempted")
        identity_session = None
        for provider, refresh in [
            (self.token_provider, False),
            (self.refresh_token_provider, True),
        ]:
            try:
                parts = provider.parse(token)
            except InvalidTokenException:
                continue
            candidate = (
                await self.get_by_refresh_token_identifier(parts.identifier)
                if refresh
                else await self.get_by_token_identifier(parts.identifier)
            )
            if candidate is None:
                continue
            verifier = (
                candidate.refresh_token_verifier
                if refresh
                else candidate.token_verifier
            )
            if verifier is None:
                continue
            valid, _ = await provider.verify_and_update(parts.secret, verifier)
            if valid:
                identity_session = candidate
                break
        if identity_session is None:
            return
        identity_session.revoked_at = get_current_timestamp()
        await self.revoke_family(identity_session)
        logger.info(
            "Identity session family revoked",
            extra={"family_id": identity_session.family_id},
        )

    async def _create_session(
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
        generated = await self.token_provider.generate()
        refresh_generated = None
        if refresh_token:
            refresh_generated = await self.refresh_token_provider.generate()
            if refresh_token_expires_at is None:
                refresh_token_expires_at = now + int(
                    self.refresh_token_lifetime.total_seconds()
                )
        expires_at = now + int(self.lifetime.total_seconds())
        if refresh_token_expires_at is not None:
            expires_at = min(expires_at, refresh_token_expires_at)
        return (
            generated.token,
            refresh_generated.token if refresh_generated else None,
            IdentitySession(
                id=None,
                token_identifier=generated.identifier,
                token_verifier=generated.verifier,
                expires_at=expires_at,
                identity_id=identity_id,
                amr=amr.copy(),
                context=context.copy() if context else None,
                refresh_token_identifier=refresh_generated.identifier
                if refresh_generated
                else None,
                refresh_token_verifier=refresh_generated.verifier
                if refresh_generated
                else None,
                refresh_token_expires_at=refresh_token_expires_at
                if refresh_token
                else None,
                family_id=family_id,
            ),
        )

    async def _validate_refresh_token(self, token: str) -> IdentitySession:
        """
        Load a refresh token's session, revoking its family on reuse.

        Args:
            token: The complete refresh token.

        Returns:
            The session eligible for replacement.

        Raises:
            InvalidRefreshTokenException: If the token is unknown, disabled, or revoked.
            ExpiredRefreshTokenException: If the absolute deadline has passed.
            ReusedRefreshTokenException: If the token was consumed previously.
                Family revocation is pending in the caller's transaction.
        """
        try:
            parts = self.refresh_token_provider.parse(token)
        except InvalidTokenException:
            logger.warning("Malformed refresh token provided")
            raise InvalidRefreshTokenException() from None
        identity_session = await self.get_by_refresh_token_identifier(parts.identifier)
        if identity_session is None or identity_session.refresh_token_verifier is None:
            logger.warning("Unknown refresh token provided")
            raise InvalidRefreshTokenException()
        valid, _ = await self.refresh_token_provider.verify_and_update(
            parts.secret, identity_session.refresh_token_verifier
        )
        if not valid or identity_session.revoked_at is not None:
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

        Args:
            identity_session: The complete session model to insert.

        Returns:
            The ID of the inserted session.

        Raises:
            TokenIdentifierCollision: If the access or refresh identifiers already exist in the store.

        Abstract: Implementation contract
            If family_id is None, set the stored family_id to the generated record ID
            in the same transaction. Preserve an explicitly supplied family ID.
            For a new member of an existing family, acquire family protection
            before insertion and reject a missing or revoked family root. Retain
            that protection until the transaction ends.
            Enforce uniqueness of token identifiers (and non-null refresh identifiers).
            Return the inserted ID and leave transaction commit and rollback to the
            caller. On identifier collision, raise TokenIdentifierCollision without
            persisting changes and leave the transaction usable for retry.
        """
        ...

    @abc.abstractmethod
    async def update_verifier(self, identity_session: IdentitySession) -> None:
        """
        Upgrade an access-token verifier.

        Args:
            identity_session: The session containing the replacement access verifier.

        Abstract: Implementation contract
            Update only token_verifier by session ID in the transaction that
            protects the record. Leave commit and rollback to the caller.
        """
        ...

    @abc.abstractmethod
    async def get_by_token_identifier(
        self, token_identifier: str
    ) -> IdentitySession | None:
        """
        Retrieve a session by its access token identifier, regardless of its validity.

        Args:
            token_identifier: The access token identifier to look up.

        Returns:
            The stored session, including expired, replaced, or revoked rows,
            or None if the session or its family root is missing.

        Abstract: Implementation contract
            Match the access token identifier without filtering out expired,
            replaced, or revoked sessions. Acquire family protection before locking
            session rows and return current state protected from competing mutations
            until the caller's transaction ends. Leave commit and rollback to the
            caller.
        """
        ...

    @abc.abstractmethod
    async def get_by_refresh_token_identifier(
        self, refresh_token_identifier: str
    ) -> IdentitySession | None:
        """
        Retrieve a session by its refresh token identifier, regardless of its validity.

        Args:
            refresh_token_identifier: The refresh token identifier to look up.

        Returns:
            The stored session, including expired, replaced, or revoked rows,
            or None if the session or its family root is missing.

        Abstract: Implementation contract
            Match the refresh token identifier without filtering out expired,
            replaced, or revoked sessions; retained rows are needed for reuse
            detection. Acquire family protection before locking session rows and
            return current state protected from competing mutations until the
            caller's transaction ends. Leave commit and rollback to the caller.
        """
        ...

    @abc.abstractmethod
    async def replace(
        self, previous_session: IdentitySession, new_session: IdentitySession
    ) -> typing.Any | None:
        """
        Atomically replace a session if its refresh token is still usable.

        Args:
            previous_session: The previously retrieved session to replace.
            new_session: The complete replacement model to persist.

        Returns:
            The replacement ID, or None with no changes if the previous session
            is no longer eligible.

        Raises:
            TokenIdentifierCollision: If the new session's access or refresh
                identifiers already exist in the store.

        Abstract: Implementation contract
            Serialize with all replacements and revocations in the same family,
            for example by locking the retained initial session row before any child
            rows. Reload the previous session under that protection: its refresh
            identifier and verifier must still match, its refresh deadline must be
            in the future, and it must be neither revoked nor replaced. Reject a
            revoked or missing family root. The supplied previous_session is a
            snapshot, not proof of eligibility.

            Insert new_session with the same family ID and set the previous row's
            replaced_by_id to the new ID atomically in the caller's transaction.
            Retain family and session protection until the transaction ends.
            Leave commit and rollback to the caller. Return None without changes
            if the previous session is no longer eligible. Propagate storage
            failures. On identifier collision, raise TokenIdentifierCollision without
            persisting changes and leave the transaction usable for retry.
        """
        ...

    @abc.abstractmethod
    async def revoke_family(self, identity_session: IdentitySession) -> None:
        """
        Persist revocation of every session in the supplied session's family.

        Args:
            identity_session: The session identifying the family and revocation time.

        Abstract: Implementation contract
            Use the supplied identity_session.revoked_at for rows not yet revoked.
            Preserve earlier revocation timestamps, identifiers, verifiers, and
            lineage. Serialize with all replacements and revocations in the family,
            for example by locking its retained initial session row before any child
            rows.

            Apply revocation in the caller's transaction and retain family and
            session protection until the transaction ends. Leave commit and rollback
            to the caller. Revocation becomes durable on commit; a rollback restores
            the previous state. Missing or already-revoked families succeed without
            error.
        """
        ...
