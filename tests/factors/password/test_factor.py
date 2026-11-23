from collections.abc import AsyncGenerator
from typing import Never
from unittest.mock import AsyncMock, Mock

import pytest
import sqlalchemy
from pwdlib.hashers.argon2 import Argon2Hasher
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from reauth.factors.password import (
    AlreadyEnrolledPasswordException,
    IdentityNotFoundException,
    InvalidPasswordException,
    InvalidPasswordResetTokenException,
    NotEnrolledPasswordException,
    PasswordEnrollment,
)
from reauth.factors.password.hashing import PasswordHashGenerationException
from reauth.integrations.sqlalchemy.password import SQLAlchemyPasswordFactor
from reauth.timestamp import get_current_timestamp
from reauth.tokens import ChecksummedTokenProvider, HMACTokenVerifier, TokenParts

sqlalchemy_meta = sqlalchemy.MetaData()
users_table = sqlalchemy.Table(
    "password_users",
    sqlalchemy_meta,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("password_hash", sqlalchemy.Text, nullable=True),
    sqlalchemy.Column(
        "reset_token_identifier", sqlalchemy.String(255), nullable=True, unique=True
    ),
    sqlalchemy.Column("reset_token_verifier", sqlalchemy.Text, nullable=True),
    sqlalchemy.Column("reset_token_expires_at", sqlalchemy.BigInteger, nullable=True),
)


@pytest.fixture
async def sqlalchemy_connection(
    sqlalchemy_integration_engine: AsyncEngine,
) -> AsyncGenerator[AsyncConnection]:
    async with sqlalchemy_integration_engine.begin() as connection:
        await connection.run_sync(sqlalchemy_meta.create_all)
        yield connection
        await connection.run_sync(sqlalchemy_meta.drop_all)


@pytest.fixture
async def factor(sqlalchemy_connection: AsyncConnection) -> SQLAlchemyPasswordFactor:
    factor = SQLAlchemyPasswordFactor(
        sqlalchemy_connection,
        users_table,
        token_provider=ChecksummedTokenProvider(
            prefix="reset_",
            verifier=HMACTokenVerifier(current_key_id="test", keys={"test": b"x" * 32}),
        ),
    )
    await sqlalchemy_connection.execute(
        sqlalchemy.insert(users_table),
        [
            {"id": 1, "password_hash": factor.password_hash.hash("original")},
            {"id": 2, "password_hash": None},
        ],
    )
    return factor


@pytest.fixture
async def reset_token(factor: SQLAlchemyPasswordFactor) -> str:
    generated = await factor.token_provider.generate()
    await factor.connection.execute(
        sqlalchemy.update(users_table)
        .where(users_table.c.id == 1)
        .values(
            reset_token_identifier=generated.identifier,
            reset_token_verifier=generated.verifier,
            reset_token_expires_at=get_current_timestamp() + 1800,
        )
    )
    return generated.token


async def stored_enrollment(
    factor: SQLAlchemyPasswordFactor, identity_id: int
) -> PasswordEnrollment:
    row = (
        (
            await factor.connection.execute(
                sqlalchemy.select(users_table).where(users_table.c.id == identity_id)
            )
        )
        .mappings()
        .one()
    )
    return PasswordEnrollment(identity_id=row["id"], **row)


@pytest.mark.anyio
class TestPasswordEnroll:
    async def test_enroll(self, factor: SQLAlchemyPasswordFactor) -> None:
        assert await factor.get_enrollment(2) is None
        enrollment = await factor.enroll(2, "new")
        assert enrollment == await stored_enrollment(factor, 2)
        assert enrollment.password_hash is not None
        assert factor.password_hash.verify("new", enrollment.password_hash)
        with pytest.raises(AlreadyEnrolledPasswordException):
            await factor.enroll(2, "other")
        with pytest.raises(IdentityNotFoundException):
            await factor.enroll(3, "new")


@pytest.mark.anyio
class TestPasswordVerify:
    async def test_verify(self, factor: SQLAlchemyPasswordFactor) -> None:
        assert (await factor.verify(1, "original")).identity_id == 1
        with pytest.raises(InvalidPasswordException):
            await factor.verify(1, "wrong")

    @pytest.mark.parametrize("identity_id", [None, 2, 3])
    async def test_verify_without_enrollment(
        self,
        factor: SQLAlchemyPasswordFactor,
        monkeypatch: pytest.MonkeyPatch,
        identity_id: int | None,
    ) -> None:
        hash_password = Mock(return_value="discarded")
        lookup = AsyncMock(wraps=factor.get_by_identity_id)
        update = AsyncMock()
        monkeypatch.setattr(factor.password_hash, "hash", hash_password)
        monkeypatch.setattr(factor, "get_by_identity_id", lookup)
        monkeypatch.setattr(factor, "update", update)

        with pytest.raises(NotEnrolledPasswordException):
            await factor.verify(identity_id, "wrong")

        hash_password.assert_called_once_with("wrong")
        if identity_id is None:
            lookup.assert_not_awaited()
        else:
            lookup.assert_awaited_once_with(identity_id)
        update.assert_not_awaited()

    async def test_verify_rehash(self, factor: SQLAlchemyPasswordFactor) -> None:
        old = Argon2Hasher(time_cost=1).hash("original")
        await factor.connection.execute(
            sqlalchemy.update(users_table)
            .where(users_table.c.id == 1)
            .values(password_hash=old)
        )
        enrollment = await factor.verify(1, "original")
        assert enrollment.password_hash != old
        assert enrollment == await stored_enrollment(factor, 1)


@pytest.mark.anyio
class TestPasswordReset:
    async def test_reset_replacement_and_replay(
        self, factor: SQLAlchemyPasswordFactor
    ) -> None:
        first = await factor.forgot_password(1)
        second = await factor.forgot_password(1)
        assert first != second
        with pytest.raises(InvalidPasswordResetTokenException):
            await factor.reset_password(first, "new")
        enrollment = await factor.reset_password(second, "new")
        assert enrollment.password_hash is not None
        assert factor.password_hash.verify("new", enrollment.password_hash)
        assert enrollment.reset_token_identifier is None
        assert enrollment.reset_token_verifier is None
        assert enrollment.reset_token_expires_at is None
        with pytest.raises(InvalidPasswordResetTokenException):
            await factor.reset_password(second, "other")

    async def test_reset_invalid_and_expired(
        self,
        factor: SQLAlchemyPasswordFactor,
        reset_token: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        token = reset_token
        before = await stored_enrollment(factor, 1)
        parts = factor.token_provider.parse(token)

        monkeypatch.setattr(
            factor.token_provider,
            "parse",
            lambda _: TokenParts(parts.identifier, "wrong"),
        )
        with pytest.raises(InvalidPasswordResetTokenException):
            await factor.reset_password(token, "new")
        assert await stored_enrollment(factor, 1) == before
        monkeypatch.undo()
        monkeypatch.setattr(
            "reauth.factors.password.get_current_timestamp",
            lambda: before.reset_token_expires_at,
        )
        with pytest.raises(InvalidPasswordResetTokenException):
            await factor.reset_password(token, "new")
        with pytest.raises(InvalidPasswordResetTokenException):
            await factor.reset_password("malformed", "new")
        assert await stored_enrollment(factor, 1) == before

    async def test_hash_failure_preserves_reset(
        self,
        factor: SQLAlchemyPasswordFactor,
        reset_token: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        token = reset_token
        before = await stored_enrollment(factor, 1)

        def fail(*args: object, **kwargs: object) -> Never:
            raise PasswordHashGenerationException()

        monkeypatch.setattr(factor.password_hash, "hash", fail)
        with pytest.raises(PasswordHashGenerationException):
            await factor.reset_password(token, "new")
        assert await stored_enrollment(factor, 1) == before


@pytest.mark.anyio
class TestPasswordUpdate:
    async def test_update_clears_reset(
        self, factor: SQLAlchemyPasswordFactor, reset_token: str
    ) -> None:
        token = reset_token
        before = await stored_enrollment(factor, 1)
        with pytest.raises(InvalidPasswordException):
            await factor.update_password(1, "wrong", "new")
        assert await stored_enrollment(factor, 1) == before
        enrollment = await factor.update_password(1, "original", "new")
        assert enrollment.password_hash is not None
        assert factor.password_hash.verify("new", enrollment.password_hash)
        with pytest.raises(InvalidPasswordResetTokenException):
            await factor.reset_password(token, "other")
