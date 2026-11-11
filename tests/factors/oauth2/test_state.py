import dataclasses

import pytest
from sqlalchemy import insert, update

from reauth.factors.oauth2.state import (
    ExpiredStateException,
    InvalidStateException,
    OAuth2State,
)
from reauth.timestamp import get_current_timestamp

from .conftest import SQLAlchemyOAuth2StateService, oauth2_state_table


@pytest.fixture
async def state_data(
    oauth2_state_service: SQLAlchemyOAuth2StateService,
) -> tuple[str, OAuth2State]:
    generated = await oauth2_state_service.token_provider.generate()
    state = OAuth2State(
        id=42,
        token_identifier=generated.identifier,
        token_verifier=generated.verifier,
        provider="google",
        redirect_uri="https://example.com/callback",
        code_verifier="test_verifier",
        nonce=None,
        identity_id=None,
        scope=None,
        expires_at=get_current_timestamp() + 3600,
        context={"auth_session_id": 789, "custom_data": "test"},
    )
    await oauth2_state_service.connection.execute(
        insert(oauth2_state_table).values(**dataclasses.asdict(state))
    )
    return generated.token, state


@pytest.mark.anyio
class TestOAuth2StateCreate:
    async def test_returns_state_token_and_state(
        self, oauth2_state_service: SQLAlchemyOAuth2StateService
    ) -> None:
        state_token, oauth2_state = await oauth2_state_service.create(
            provider="google",
            redirect_uri="https://example.com/callback",
            code_verifier="test_verifier",
        )

        assert isinstance(state_token, str)
        assert len(state_token) > 0
        assert isinstance(oauth2_state, OAuth2State)
        assert oauth2_state.id is not None
        assert oauth2_state.provider == "google"
        assert oauth2_state.code_verifier == "test_verifier"
        assert oauth2_state.redirect_uri == "https://example.com/callback"
        assert oauth2_state.nonce is None
        assert oauth2_state.identity_id is None
        assert oauth2_state.expires_at > 0

    async def test_with_nonce(
        self, oauth2_state_service: SQLAlchemyOAuth2StateService
    ) -> None:
        _, oauth2_state = await oauth2_state_service.create(
            provider="github",
            redirect_uri="https://example.com/callback",
            nonce="test_nonce",
        )

        assert oauth2_state.nonce == "test_nonce"

    async def test_with_identity_id(
        self, oauth2_state_service: SQLAlchemyOAuth2StateService
    ) -> None:
        _, oauth2_state = await oauth2_state_service.create(
            provider="google",
            redirect_uri="https://example.com/callback",
            identity_id=123,
        )

        assert oauth2_state.identity_id == 123

    async def test_state_token_has_prefix(
        self, oauth2_state_service: SQLAlchemyOAuth2StateService
    ) -> None:
        state_token, _ = await oauth2_state_service.create(
            provider="google",
            redirect_uri="https://example.com/callback",
        )

        assert state_token.startswith("reauth_oauth2_")

    async def test_without_code_verifier(
        self, oauth2_state_service: SQLAlchemyOAuth2StateService
    ) -> None:
        _, oauth2_state = await oauth2_state_service.create(
            provider="google",
            redirect_uri="https://example.com/callback",
        )

        assert oauth2_state.code_verifier is None

    async def test_with_scope(
        self, oauth2_state_service: SQLAlchemyOAuth2StateService
    ) -> None:
        _, oauth2_state = await oauth2_state_service.create(
            provider="google",
            redirect_uri="https://example.com/callback",
            scope=["read", "write", "profile"],
        )

        assert oauth2_state.scope == ["read", "write", "profile"]

    async def test_without_scope(
        self, oauth2_state_service: SQLAlchemyOAuth2StateService
    ) -> None:
        _, oauth2_state = await oauth2_state_service.create(
            provider="google",
            redirect_uri="https://example.com/callback",
        )

        assert oauth2_state.scope is None

    async def test_with_context(
        self, oauth2_state_service: SQLAlchemyOAuth2StateService
    ) -> None:
        _, oauth2_state = await oauth2_state_service.create(
            provider="google",
            redirect_uri="https://example.com/callback",
            auth_session_id=456,
            original_url="/dashboard",
        )

        assert oauth2_state.context == {
            "auth_session_id": 456,
            "original_url": "/dashboard",
        }

    async def test_without_context(
        self, oauth2_state_service: SQLAlchemyOAuth2StateService
    ) -> None:
        _, oauth2_state = await oauth2_state_service.create(
            provider="google",
            redirect_uri="https://example.com/callback",
        )

        assert oauth2_state.context is None


@pytest.mark.anyio
class TestOAuth2StateConsume:
    async def test_consume_valid_state(
        self,
        oauth2_state_service: SQLAlchemyOAuth2StateService,
        state_data: tuple[str, OAuth2State],
    ) -> None:
        state_token, expected_state = state_data
        oauth2_state = await oauth2_state_service.consume(state_token)
        assert oauth2_state == expected_state

    async def test_consume_invalid_state(
        self, oauth2_state_service: SQLAlchemyOAuth2StateService
    ) -> None:
        with pytest.raises(InvalidStateException):
            await oauth2_state_service.consume("invalid_state_token")

    async def test_consume_deletes_state(
        self,
        oauth2_state_service: SQLAlchemyOAuth2StateService,
        state_data: tuple[str, OAuth2State],
    ) -> None:
        state_token, _ = state_data
        # First consume should succeed
        await oauth2_state_service.consume(state_token)
        assert (
            await oauth2_state_service.get_by_token_identifier(
                state_data[1].token_identifier
            )
            is None
        )

        # Second consume with same token should fail (already deleted)
        with pytest.raises(InvalidStateException):
            await oauth2_state_service.consume(state_token)

    async def test_consume_expired_state(
        self,
        oauth2_state_service: SQLAlchemyOAuth2StateService,
        state_data: tuple[str, OAuth2State],
    ) -> None:
        state_token, _ = state_data
        await oauth2_state_service.connection.execute(
            update(oauth2_state_table)
            .where(oauth2_state_table.c.id == state_data[1].id)
            .values(expires_at=0)
        )
        with pytest.raises(ExpiredStateException):
            await oauth2_state_service.consume(state_token)

    async def test_consume_preserves_context(
        self,
        oauth2_state_service: SQLAlchemyOAuth2StateService,
        state_data: tuple[str, OAuth2State],
    ) -> None:
        oauth2_state = await oauth2_state_service.consume(state_data[0])
        assert oauth2_state.context == {"auth_session_id": 789, "custom_data": "test"}
