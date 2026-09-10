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
    id: typing.Any | None
    token_hash: TokenHash
    expires_at: int
    identity_id: typing.Any
    amr: list[AuthenticationMethodReference]
    context: dict[str, typing.Any] | None = None

    def is_expired(self) -> bool:
        return get_current_timestamp() >= self.expires_at


class IdentitySessionException(ReauthException):
    pass


class InvalidSessionTokenException(IdentitySessionException):
    pass


class ExpiredSessionException(IdentitySessionException):
    pass


class IdentitySessionService(abc.ABC):
    def __init__(
        self,
        *,
        hash_secret: str,
        token_prefix: str = "reauth_is_",
        lifetime: datetime.timedelta = datetime.timedelta(hours=24),
    ) -> None:
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
        logger.debug(
            "Identity session revocation attempted",
            extra={"session_id": identity_session.id},
        )
        await self.delete(identity_session)
        logger.info(
            "Identity session revoked", extra={"session_id": identity_session.id}
        )

    @abc.abstractmethod
    async def insert(self, identity_session: IdentitySession) -> typing.Any: ...

    @abc.abstractmethod
    async def get_by_token_hash(
        self, token_hash: TokenHash
    ) -> IdentitySession | None: ...

    @abc.abstractmethod
    async def delete(self, identity_session: IdentitySession) -> None: ...
