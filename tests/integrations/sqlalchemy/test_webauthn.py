import asyncio
import dataclasses

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine

from reauth.factors.webauthn import (
    InvalidAuthenticationException,
    InvalidRegistrationException,
    WebAuthnEnrollment,
)
from reauth.factors.webauthn.state import Ceremony, InvalidStateException
from reauth.tokens import TokenIdentifierCollision
from tests.webauthn import Factor, make_factor, response, seed_enrollment, seed_state


@pytest.mark.anyio
async def test_revoke_and_rp_uniqueness(
    webauthn_factor: Factor, webauthn_tables: tuple[sa.Table, sa.Table]
) -> None:
    await seed_enrollment(webauthn_factor, webauthn_tables)
    await seed_enrollment(webauthn_factor, webauthn_tables, b"spare")
    first, spare = await webauthn_factor.get_enrollments(42)
    with pytest.raises(IntegrityError):
        async with webauthn_factor.connection.begin_nested():
            await webauthn_factor.insert(
                dataclasses.replace(
                    first, id=None, identity_id=8, factor_identifier="another"
                )
            )
    await webauthn_factor.delete(first)
    assert await webauthn_factor.get_enrollments(42) == [spare]


@pytest.mark.anyio
async def test_state_identifier_collision(
    webauthn_factor: Factor, webauthn_tables: tuple[sa.Table, sa.Table]
) -> None:
    token = await seed_state(webauthn_factor, webauthn_tables)
    state = await webauthn_factor.state_service.get_by_token_identifier(
        webauthn_factor.state_service.token_provider.parse(token).identifier
    )
    assert state is not None
    with pytest.raises(TokenIdentifierCollision):
        await webauthn_factor.state_service.insert(dataclasses.replace(state, id=None))
    assert (
        await webauthn_factor.state_service.get_by_token_identifier(
            state.token_identifier
        )
        == state
    )


@pytest.mark.anyio
@pytest.mark.parametrize("ceremony", ["enrollment", "authentication"])
@pytest.mark.parametrize("commit", [True, False])
async def test_rejected_ceremony_transaction_ownership(
    sqlalchemy_integration_engine: AsyncEngine,
    webauthn_tables: tuple[sa.Table, sa.Table],
    ceremony: Ceremony,
    commit: bool,
) -> None:
    async with sqlalchemy_integration_engine.begin() as connection:
        factor = make_factor(connection, webauthn_tables)
        token = await seed_state(factor, webauthn_tables, ceremony, identity_id=42)

    async with sqlalchemy_integration_engine.connect() as connection:
        transaction = await connection.begin()
        factor = make_factor(connection, webauthn_tables)
        if ceremony == "enrollment":
            with pytest.raises(InvalidRegistrationException):
                await factor.finish_enrollment(
                    state_token=token, session_id=5, credential={}
                )
        else:
            with pytest.raises(InvalidAuthenticationException):
                await factor.finish_authentication(
                    state_token=token, session_id=5, credential={}
                )
        if commit:
            await transaction.commit()
        else:
            await transaction.rollback()

    async with sqlalchemy_integration_engine.connect() as connection:
        state_id = await connection.scalar(sa.select(webauthn_tables[1].c.id))
        assert (state_id is None) == commit


@pytest.mark.anyio
async def test_concurrent_finish(
    sqlalchemy_integration_engine: AsyncEngine,
    webauthn_tables: tuple[sa.Table, sa.Table],
) -> None:
    if sqlalchemy_integration_engine.dialect.name == "sqlite":
        pytest.skip("SQLite has no row-level locks")
    async with sqlalchemy_integration_engine.begin() as connection:
        webauthn_factor = make_factor(connection, webauthn_tables)
        await seed_enrollment(webauthn_factor, webauthn_tables)
        token = await seed_state(webauthn_factor, webauthn_tables)

    async def finish() -> WebAuthnEnrollment:
        async with sqlalchemy_integration_engine.begin() as connection:
            return await make_factor(connection, webauthn_tables).finish_authentication(
                state_token=token, session_id=5, credential=response()
            )

    results = await asyncio.gather(finish(), finish(), return_exceptions=True)
    assert sum(isinstance(result, WebAuthnEnrollment) for result in results) == 1
    assert sum(isinstance(result, InvalidStateException) for result in results) == 1
