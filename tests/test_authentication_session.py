import dataclasses
from collections.abc import AsyncGenerator

import pytest
from sqlalchemy import (
    MetaData,
    delete,
    insert,
    select,
)
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from reauth.amr import AuthenticationMethodReference
from reauth.authentication_session import (
    AuthenticationSession,
    ExpiredSessionException,
    FactorsRemainingException,
    IdentityNotAttachedException,
    InvalidSessionTokenException,
    UnavailableFactorException,
)
from reauth.factors import FactorBase
from reauth.integrations.sqlalchemy import (
    SQLAlchemyAuthenticationSessionService,
    create_authentication_session_table,
)
from reauth.timestamp import get_current_timestamp
from reauth.tokens import (
    ChecksummedTokenProvider,
    HMACTokenVerifier,
)


def make_provider(prefix: str = "reauth_as_") -> ChecksummedTokenProvider:
    return ChecksummedTokenProvider(
        prefix=prefix,
        verifier=HMACTokenVerifier(current_key_id="test", keys={"test": b"t" * 32}),
    )


sqlalchemy_meta = MetaData()
authentication_session_table = create_authentication_session_table(sqlalchemy_meta)


@dataclasses.dataclass
class DummyPasswordFactorEnrollment:
    id: int | None
    identity_id: int


class DummyPasswordFactor(FactorBase[DummyPasswordFactorEnrollment]):
    """Dummy factor for testing purposes that simulates a password-based authentication method."""

    AMR = AuthenticationMethodReference.PWD

    def __init__(self) -> None:
        super().__init__(identifier="dummy_password", step=0)

    async def get_enrollment(
        self, identity_id: int
    ) -> DummyPasswordFactorEnrollment | None:
        if identity_id != 1:
            return None
        return DummyPasswordFactorEnrollment(id=1, identity_id=identity_id)


class DummySSOFactor(FactorBase[DummyPasswordFactorEnrollment]):
    AMR = AuthenticationMethodReference.OAUTH2

    def __init__(self) -> None:
        super().__init__(identifier="dummy_sso", step=0, advance_by=2)

    async def get_enrollment(
        self, identity_id: int
    ) -> DummyPasswordFactorEnrollment | None:
        if identity_id != 1:
            return None
        return DummyPasswordFactorEnrollment(id=1, identity_id=identity_id)


@dataclasses.dataclass
class DummyMFAFactorEnrollment:
    id: int | None
    identity_id: int


class DummyMFAFactor(FactorBase[DummyMFAFactorEnrollment]):
    """Dummy factor for testing purposes that simulates a multi-factor authentication method."""

    AMR = AuthenticationMethodReference.MFA

    def __init__(self) -> None:
        super().__init__(identifier="dummy_mfa", step=1)

    async def get_enrollment(self, identity_id: int) -> DummyMFAFactorEnrollment | None:
        if identity_id != 1:
            return None
        return DummyMFAFactorEnrollment(id=1, identity_id=identity_id)


@pytest.fixture
async def sqlalchemy_connection(
    sqlalchemy_integration_engine: AsyncEngine,
) -> AsyncGenerator[AsyncConnection]:
    """Fixture that creates tables and provides a connection for testing."""
    async with sqlalchemy_integration_engine.begin() as conn:
        await conn.run_sync(sqlalchemy_meta.create_all)
        yield conn
        await conn.run_sync(sqlalchemy_meta.drop_all)


@pytest.fixture
def password_factor() -> DummyPasswordFactor:
    """Fixture that provides an instance of DummyPasswordFactor."""
    return DummyPasswordFactor()


@pytest.fixture
def mfa_factor() -> DummyMFAFactor:
    """Fixture that provides an instance of DummyMFAFactor."""
    return DummyMFAFactor()


@pytest.fixture
def authentication_session_service(
    sqlalchemy_connection: AsyncConnection,
    password_factor: DummyPasswordFactor,
    mfa_factor: DummyMFAFactor,
) -> SQLAlchemyAuthenticationSessionService:
    """Fixture that provides an instance of SQLAlchemyAuthenticationSessionService."""
    return SQLAlchemyAuthenticationSessionService(
        connection=sqlalchemy_connection,
        table=authentication_session_table,
        token_provider=make_provider(),
        factors={password_factor, mfa_factor},
    )


@pytest.fixture
async def authentication_session_data(
    authentication_session_service: SQLAlchemyAuthenticationSessionService,
) -> tuple[str, AuthenticationSession]:
    generated = await authentication_session_service.token_provider.generate()
    return generated.token, AuthenticationSession(
        id=1,
        token_identifier=generated.identifier,
        token_verifier=generated.verifier,
        expires_at=get_current_timestamp() + 3600,
        identity_id=None,
    )


@pytest.mark.anyio
class TestAuthenticationSessionStart:
    async def test_returns_valid_session(
        self, authentication_session_service: SQLAlchemyAuthenticationSessionService
    ) -> None:
        token, session = await authentication_session_service.start()
        assert isinstance(session, AuthenticationSession)
        assert session.id is not None
        assert session.expires_at > get_current_timestamp()
        assert session.identity_id is None

        parts = authentication_session_service.token_provider.parse(token)
        assert session.token_identifier == parts.identifier
        assert await authentication_session_service.token_provider.verify_and_update(
            parts.secret, session.token_verifier
        ) == (True, None)

    async def test_start_with_context(
        self, authentication_session_service: SQLAlchemyAuthenticationSessionService
    ) -> None:
        """Test that context can be passed to start() and stored in session."""
        _token, session = await authentication_session_service.start(
            return_to="https://example.com/dashboard",
            original_path="/protected-page",
        )

        assert session.context == {
            "return_to": "https://example.com/dashboard",
            "original_path": "/protected-page",
        }

    async def test_start_without_context(
        self, authentication_session_service: SQLAlchemyAuthenticationSessionService
    ) -> None:
        """Test that context is None when no context is passed."""
        _token, session = await authentication_session_service.start()

        assert session.context is None


@pytest.mark.anyio
class TestAuthenticationSessionValidate:
    async def test_not_existing_session(
        self, authentication_session_service: SQLAlchemyAuthenticationSessionService
    ) -> None:
        with pytest.raises(InvalidSessionTokenException):
            await authentication_session_service.validate("token")

    async def test_expired_session(
        self, authentication_session_service: SQLAlchemyAuthenticationSessionService
    ) -> None:
        generated = await authentication_session_service.token_provider.generate()
        token = generated.token
        await authentication_session_service.insert(
            AuthenticationSession(
                id=None,
                token_identifier=generated.identifier,
                token_verifier=generated.verifier,
                expires_at=0,
                identity_id=None,
                context=None,
            )
        )

        with pytest.raises(ExpiredSessionException):
            await authentication_session_service.validate(token)

    async def test_valid_session(
        self, authentication_session_service: SQLAlchemyAuthenticationSessionService
    ) -> None:
        generated = await authentication_session_service.token_provider.generate()
        token = generated.token
        session_id = await authentication_session_service.insert(
            AuthenticationSession(
                id=None,
                token_identifier=generated.identifier,
                token_verifier=generated.verifier,
                expires_at=get_current_timestamp() + 3600,
                identity_id=None,
                context=None,
            )
        )

        session = await authentication_session_service.validate(token)
        assert session.id == session_id


@pytest.mark.anyio
class TestGetAvailableFactors:
    async def test_no_identity_zero_factor(
        self, authentication_session_service: SQLAlchemyAuthenticationSessionService
    ) -> None:
        generated = await authentication_session_service.token_provider.generate()
        session = AuthenticationSession(
            id=None,
            token_identifier=generated.identifier,
            token_verifier=generated.verifier,
            expires_at=get_current_timestamp() + 3600,
            identity_id=None,
            context=None,
        )
        session.id = await authentication_session_service.insert(session)

        factors = await authentication_session_service.get_available_factors(session)

        assert len(factors) == 1
        assert isinstance(next(iter(factors)), DummyPasswordFactor)

    async def test_identity_one_factor_enrolled(
        self, authentication_session_service: SQLAlchemyAuthenticationSessionService
    ) -> None:
        generated = await authentication_session_service.token_provider.generate()
        session = AuthenticationSession(
            id=None,
            token_identifier=generated.identifier,
            token_verifier=generated.verifier,
            expires_at=get_current_timestamp() + 3600,
            identity_id=1,
            amr=[AuthenticationMethodReference.PWD],
            used_factors=["dummy_password"],
            context=None,
            step=1,
        )
        session.id = await authentication_session_service.insert(session)

        factors = await authentication_session_service.get_available_factors(session)

        assert len(factors) == 1
        assert isinstance(next(iter(factors)), DummyMFAFactor)

    async def test_identity_one_factor_not_enrolled(
        self, authentication_session_service: SQLAlchemyAuthenticationSessionService
    ) -> None:
        generated = await authentication_session_service.token_provider.generate()
        session = AuthenticationSession(
            id=None,
            token_identifier=generated.identifier,
            token_verifier=generated.verifier,
            expires_at=get_current_timestamp() + 3600,
            identity_id=2,
            amr=[AuthenticationMethodReference.PWD],
            used_factors=["dummy_password"],
            context=None,
            step=1,
        )
        session.id = await authentication_session_service.insert(session)

        factors = await authentication_session_service.get_available_factors(session)

        assert len(factors) == 0


@pytest.mark.anyio
class TestAdvance:
    async def test_invalid_token(
        self,
        authentication_session_service: SQLAlchemyAuthenticationSessionService,
        password_factor: DummyPasswordFactor,
    ) -> None:
        with pytest.raises(InvalidSessionTokenException):
            await authentication_session_service.advance("unknown", 1, password_factor)

    async def test_expired_session(
        self,
        authentication_session_service: SQLAlchemyAuthenticationSessionService,
        password_factor: DummyPasswordFactor,
        sqlalchemy_connection: AsyncConnection,
        authentication_session_data: tuple[str, AuthenticationSession],
    ) -> None:
        token, session = authentication_session_data
        session.expires_at = 0
        await sqlalchemy_connection.execute(
            insert(authentication_session_table).values(**dataclasses.asdict(session))
        )

        with pytest.raises(ExpiredSessionException):
            await authentication_session_service.advance(token, 1, password_factor)

        result = await sqlalchemy_connection.execute(
            select(authentication_session_table)
        )
        assert result.mappings().one() == dataclasses.asdict(session)

    async def test_uses_current_step(
        self,
        authentication_session_service: SQLAlchemyAuthenticationSessionService,
        password_factor: DummyPasswordFactor,
        sqlalchemy_connection: AsyncConnection,
        authentication_session_data: tuple[str, AuthenticationSession],
    ) -> None:
        token, session = authentication_session_data
        session.identity_id = 1
        session.step = 1
        session.amr = [AuthenticationMethodReference.PWD]
        session.used_factors = ["dummy_password"]
        await sqlalchemy_connection.execute(
            insert(authentication_session_table).values(**dataclasses.asdict(session))
        )

        with pytest.raises(UnavailableFactorException):
            await authentication_session_service.advance(token, 1, password_factor)

        result = await sqlalchemy_connection.execute(
            select(authentication_session_table)
        )
        assert result.mappings().one() == dataclasses.asdict(session)

    async def test_no_identity_zero_factor(
        self,
        authentication_session_service: SQLAlchemyAuthenticationSessionService,
        password_factor: DummyPasswordFactor,
    ) -> None:
        generated = await authentication_session_service.token_provider.generate()
        token = generated.token
        session = AuthenticationSession(
            id=None,
            token_identifier=generated.identifier,
            token_verifier=generated.verifier,
            expires_at=get_current_timestamp() + 3600,
            identity_id=None,
            context=None,
        )
        session.id = await authentication_session_service.insert(session)

        updated_session = await authentication_session_service.advance(
            token, 1, password_factor
        )

        assert updated_session.id == session.id
        assert updated_session.amr == [AuthenticationMethodReference.PWD]
        assert updated_session.used_factors == ["dummy_password"]
        assert updated_session.step == 1

    async def test_factor_can_skip_next_step(
        self,
        sqlalchemy_connection: AsyncConnection,
        mfa_factor: DummyMFAFactor,
    ) -> None:
        trusted_factor = DummySSOFactor()
        authentication_session_service = SQLAlchemyAuthenticationSessionService(
            connection=sqlalchemy_connection,
            table=authentication_session_table,
            token_provider=make_provider(),
            factors={trusted_factor, mfa_factor},
        )
        token, _session = await authentication_session_service.start()

        updated_session = await authentication_session_service.advance(
            token, 1, trusted_factor
        )

        assert updated_session.step == 2
        assert (
            await authentication_session_service.get_available_factors(updated_session)
            == set()
        )

    async def test_identity_one_factor_enrolled(
        self,
        authentication_session_service: SQLAlchemyAuthenticationSessionService,
        mfa_factor: DummyMFAFactor,
    ) -> None:
        generated = await authentication_session_service.token_provider.generate()
        token = generated.token
        session = AuthenticationSession(
            id=None,
            token_identifier=generated.identifier,
            token_verifier=generated.verifier,
            expires_at=get_current_timestamp() + 3600,
            identity_id=1,
            amr=[AuthenticationMethodReference.PWD],
            used_factors=["dummy_password"],
            context=None,
            step=1,
        )
        session.id = await authentication_session_service.insert(session)

        updated_session = await authentication_session_service.advance(
            token, 1, mfa_factor
        )

        assert updated_session.id == session.id
        assert updated_session.amr == [
            AuthenticationMethodReference.PWD,
            AuthenticationMethodReference.MFA,
        ]
        assert updated_session.used_factors == ["dummy_password", "dummy_mfa"]

    async def test_identity_one_factor_not_enrolled(
        self,
        authentication_session_service: SQLAlchemyAuthenticationSessionService,
        mfa_factor: DummyMFAFactor,
    ) -> None:
        generated = await authentication_session_service.token_provider.generate()
        token = generated.token
        session = AuthenticationSession(
            id=None,
            token_identifier=generated.identifier,
            token_verifier=generated.verifier,
            expires_at=get_current_timestamp() + 3600,
            identity_id=2,
            amr=[AuthenticationMethodReference.PWD],
            used_factors=["dummy_password"],
            context=None,
            step=1,
        )
        session.id = await authentication_session_service.insert(session)

        with pytest.raises(UnavailableFactorException):
            await authentication_session_service.advance(token, 1, mfa_factor)


@pytest.mark.anyio
class TestComplete:
    async def test_invalid_token(
        self, authentication_session_service: SQLAlchemyAuthenticationSessionService
    ) -> None:
        with pytest.raises(InvalidSessionTokenException):
            await authentication_session_service.complete("unknown")

    async def test_expired_session(
        self,
        authentication_session_service: SQLAlchemyAuthenticationSessionService,
        sqlalchemy_connection: AsyncConnection,
        authentication_session_data: tuple[str, AuthenticationSession],
    ) -> None:
        token, session = authentication_session_data
        session.expires_at = 0
        session.identity_id = 1
        session.step = 2
        await sqlalchemy_connection.execute(
            insert(authentication_session_table).values(**dataclasses.asdict(session))
        )

        with pytest.raises(ExpiredSessionException):
            await authentication_session_service.complete(token)

        result = await sqlalchemy_connection.execute(
            select(authentication_session_table)
        )
        assert result.mappings().one() == dataclasses.asdict(session)

    async def test_already_completed_session(
        self,
        authentication_session_service: SQLAlchemyAuthenticationSessionService,
        sqlalchemy_connection: AsyncConnection,
        authentication_session_data: tuple[str, AuthenticationSession],
    ) -> None:
        token, session = authentication_session_data
        session.identity_id = 1
        session.step = 2
        session.amr = [
            AuthenticationMethodReference.PWD,
            AuthenticationMethodReference.MFA,
        ]
        await sqlalchemy_connection.execute(
            insert(authentication_session_table).values(**dataclasses.asdict(session))
        )
        await sqlalchemy_connection.execute(
            delete(authentication_session_table).where(
                authentication_session_table.c.id == session.id
            )
        )

        with pytest.raises(InvalidSessionTokenException):
            await authentication_session_service.complete(token)

    async def test_returns_identity_and_amr(
        self,
        authentication_session_service: SQLAlchemyAuthenticationSessionService,
        password_factor: DummyPasswordFactor,
        mfa_factor: DummyMFAFactor,
    ) -> None:
        token, session = await authentication_session_service.start()
        session = await authentication_session_service.advance(
            token, 1, password_factor
        )
        session = await authentication_session_service.advance(token, 1, mfa_factor)

        identity_id, amr = await authentication_session_service.complete(token)
        assert identity_id == 1
        assert amr == [
            AuthenticationMethodReference.PWD,
            AuthenticationMethodReference.MFA,
        ]
        assert session.used_factors == ["dummy_password", "dummy_mfa"]

        # Verify session was deleted
        deleted = await authentication_session_service.get_by_token_identifier(
            session.token_identifier
        )
        assert deleted is None

    async def test_raises_identity_not_attached(
        self, authentication_session_service: SQLAlchemyAuthenticationSessionService
    ) -> None:
        token, _session = await authentication_session_service.start()

        with pytest.raises(IdentityNotAttachedException):
            await authentication_session_service.complete(token)

    async def test_raises_factors_remaining(
        self,
        authentication_session_service: SQLAlchemyAuthenticationSessionService,
        password_factor: DummyPasswordFactor,
    ) -> None:
        token, _session = await authentication_session_service.start()
        await authentication_session_service.advance(token, 1, password_factor)

        with pytest.raises(FactorsRemainingException) as exc_info:
            await authentication_session_service.complete(token)

        assert len(exc_info.value.factors) == 1
        assert isinstance(next(iter(exc_info.value.factors)), DummyMFAFactor)
