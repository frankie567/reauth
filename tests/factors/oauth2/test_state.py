import datetime

import pytest
from sqlalchemy.ext.asyncio import AsyncConnection

from reauth.factors.oauth2.state import (
    ExpiredStateException,
    InvalidStateException,
    OAuth2State,
)

from .conftest import SQLAlchemyOAuth2StateService


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
        self, oauth2_state_service: SQLAlchemyOAuth2StateService
    ) -> None:
        state_token, expected_state = await oauth2_state_service.create(
            provider="google",
            redirect_uri="https://example.com/callback",
            code_verifier="test_verifier",
        )

        oauth2_state = await oauth2_state_service.consume(state_token)

        assert oauth2_state.id == expected_state.id
        assert oauth2_state.provider == "google"
        assert oauth2_state.code_verifier == "test_verifier"

    async def test_consume_invalid_state(
        self, oauth2_state_service: SQLAlchemyOAuth2StateService
    ) -> None:
        with pytest.raises(InvalidStateException):
            await oauth2_state_service.consume("invalid_state_token")

    async def test_consume_deletes_state(
        self, oauth2_state_service: SQLAlchemyOAuth2StateService
    ) -> None:
        state_token, _ = await oauth2_state_service.create(
            provider="google",
            redirect_uri="https://example.com/callback",
        )

        # First consume should succeed
        oauth2_state = await oauth2_state_service.consume(state_token)
        assert oauth2_state is not None

        # Second consume with same token should fail (already deleted)
        with pytest.raises(InvalidStateException):
            await oauth2_state_service.consume(state_token)

    async def test_consume_expired_state(
        self, sqlalchemy_connection: AsyncConnection
    ) -> None:
        service = SQLAlchemyOAuth2StateService(
            connection=sqlalchemy_connection,
            hash_secret="test-secret",
            lifetime=datetime.timedelta(seconds=0),  # Expires immediately
        )

        state_token, _ = await service.create(
            provider="google",
            redirect_uri="https://example.com/callback",
        )

        with pytest.raises(ExpiredStateException):
            await service.consume(state_token)

    async def test_consume_preserves_context(
        self, oauth2_state_service: SQLAlchemyOAuth2StateService
    ) -> None:
        state_token, _ = await oauth2_state_service.create(
            provider="google",
            redirect_uri="https://example.com/callback",
            auth_session_id=789,
            custom_data="test",
        )

        oauth2_state = await oauth2_state_service.consume(state_token)
        assert oauth2_state.context == {"auth_session_id": 789, "custom_data": "test"}
