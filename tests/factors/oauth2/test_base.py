import dataclasses

import pytest
from sqlalchemy import insert, select, update
from sqlalchemy.ext.asyncio import AsyncConnection

from reauth.factors.oauth2.base import (
    OAuth2Account,
    OAuth2CallbackException,
    OAuth2Enrollment,
    OAuth2Factor,
    OAuth2IdentityMismatchException,
    OAuth2MissingCodeException,
    TokenResponse,
)
from reauth.factors.oauth2.state import (
    InvalidStateException,
    OAuth2State,
)

from .conftest import SQLAlchemyOAuth2StateService, oauth2_enrollment_table


class SQLAlchemyOAuth2Factor(OAuth2Factor):
    """Concrete implementation of OAuth2Factor using SQLAlchemy for testing."""

    def __init__(
        self,
        connection: AsyncConnection,
        state_service: SQLAlchemyOAuth2StateService,
        *,
        identifier: str = "provider",
        client_id: str = "test-client-id",
    ) -> None:
        self.connection = connection
        super().__init__(
            identifier=identifier,
            client_id=client_id,
            state_service=state_service,
        )

    async def get_enrollment(self, identity_id: int) -> OAuth2Enrollment | None:
        """Get enrollment by identity_id."""
        result = await self.connection.execute(
            select(oauth2_enrollment_table).where(
                oauth2_enrollment_table.c.identity_id == identity_id
            )
        )
        row = result.fetchone()
        if row is None:
            return None
        return OAuth2Enrollment(**row._asdict())

    async def get_client_secret(self) -> str:
        """Return a dummy client secret for testing purposes."""
        return "test-client-secret"

    async def get_authorization_url(
        self,
        *,
        redirect_uri: str,
        scope: list[str] | None = None,
        state: str,
        code_challenge: str | None = None,
        code_challenge_method: str | None = None,
        nonce: str | None = None,
        extra: dict[str, str] | None = None,
    ) -> str:
        return f"https://provider.example.com/auth?state={state}"

    async def exchange_code(
        self,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str | None = None,
        nonce: str | None = None,
        state: OAuth2State,
    ) -> TokenResponse:
        """Exchange code for token - returns mock data."""
        return TokenResponse(
            account_id="test-account-id",
            access_token="test-access-token",
            expires_at=3600,
            refresh_token="test-refresh-token",
            refresh_token_expires_at=7200,
        )

    async def insert(self, enrollment: OAuth2Enrollment) -> int:
        """Insert an OAuth2 enrollment into the database."""
        result = await self.connection.execute(
            insert(oauth2_enrollment_table)
            .values(**dataclasses.asdict(enrollment))
            .returning(oauth2_enrollment_table.c.id)
        )
        return result.scalar_one()

    async def update(self, enrollment: OAuth2Enrollment) -> None:
        """Update an OAuth2 enrollment in the database."""
        await self.connection.execute(
            update(oauth2_enrollment_table)
            .where(oauth2_enrollment_table.c.id == enrollment.id)
            .values(**dataclasses.asdict(enrollment))
        )

    async def get_enrollment_by_provider_and_account(
        self,
        provider: str,
        account_id: str,
    ) -> OAuth2Enrollment | None:
        """Get enrollment by provider and account_id."""
        result = await self.connection.execute(
            select(oauth2_enrollment_table).where(
                oauth2_enrollment_table.c.provider == provider,
                oauth2_enrollment_table.c.account_id == account_id,
            )
        )
        row = result.fetchone()
        if row is None:
            return None
        return OAuth2Enrollment(**row._asdict())

    async def get_profile(self, access_token: str) -> dict[str, object]:
        """Mock get_profile for testing - returns mock profile data."""
        return {
            "sub": "test-sub",
            "email": "reauth@example.com",
            "name": "Test User",
        }


@pytest.fixture
def oauth2_factor(
    sqlalchemy_connection: AsyncConnection,
    oauth2_state_service: SQLAlchemyOAuth2StateService,
) -> SQLAlchemyOAuth2Factor:
    """Fixture providing an OAuth2 factor for testing."""
    return SQLAlchemyOAuth2Factor(sqlalchemy_connection, oauth2_state_service)


@pytest.mark.anyio
class TestOAuth2FactorStart:
    async def test_returns_url_token_and_state(
        self, oauth2_factor: SQLAlchemyOAuth2Factor
    ) -> None:
        """start() returns authorization URL, state token, and state."""
        authorization_url, state_token, oauth2_state = await oauth2_factor.start(
            redirect_uri="https://example.com/callback",
        )

        assert isinstance(authorization_url, str)
        assert authorization_url.startswith("https://provider.example.com/auth?state=")
        assert isinstance(state_token, str)
        assert len(state_token) > 0
        assert state_token.startswith("reauth_oauth2_")
        assert isinstance(oauth2_state, OAuth2State)
        assert oauth2_state.provider == "provider"

    async def test_generates_pkce_with_s256(
        self, oauth2_factor: SQLAlchemyOAuth2Factor
    ) -> None:
        """start() generates PKCE code_verifier when S256 is specified."""
        _, _, oauth2_state = await oauth2_factor.start(
            redirect_uri="https://example.com/callback",
            code_challenge_method="S256",
        )

        assert oauth2_state.code_verifier is not None

    async def test_start_with_context(
        self, oauth2_factor: SQLAlchemyOAuth2Factor
    ) -> None:
        """start() stores context keyword arguments in state."""
        _, _, oauth2_state = await oauth2_factor.start(
            redirect_uri="https://example.com/callback",
            auth_session_id=123,
            return_to="/dashboard",
        )

        assert oauth2_state.context == {
            "auth_session_id": 123,
            "return_to": "/dashboard",
        }

    async def test_start_without_context(
        self, oauth2_factor: SQLAlchemyOAuth2Factor
    ) -> None:
        """start() sets context to None when no keyword arguments are passed."""
        _, _, oauth2_state = await oauth2_factor.start(
            redirect_uri="https://example.com/callback",
        )

        assert oauth2_state.context is None


@pytest.mark.anyio
class TestOAuth2FactorCallback:
    """Test OAuth2 callback functionality."""

    @pytest.mark.parametrize(
        "error,error_description",
        [
            ("access_denied", None),
            ("access_denied", "User denied access"),
            ("invalid_request", None),
            ("unauthorized_client", None),
            ("unsupported_response_type", None),
            ("invalid_scope", None),
            ("server_error", None),
            ("temporarily_unavailable", None),
            ("custom_error", None),
        ],
    )
    async def test_error_handling(
        self,
        oauth2_factor: SQLAlchemyOAuth2Factor,
        error: str,
        error_description: str | None,
    ) -> None:
        """Test that OAuth2 errors are properly handled."""
        # Create a valid state first
        _, state_token, _ = await oauth2_factor.start(
            redirect_uri="https://example.com/callback"
        )
        with pytest.raises(OAuth2CallbackException):
            await oauth2_factor.callback(
                code="some-code",
                state=state_token,
                error=error,
                error_description=error_description,
            )

    async def test_missing_code_error(
        self, oauth2_factor: SQLAlchemyOAuth2Factor
    ) -> None:
        """Test that missing code raises appropriate exception."""
        # Create a valid state first
        _, state_token, _ = await oauth2_factor.start(
            redirect_uri="https://example.com/callback"
        )
        with pytest.raises(OAuth2MissingCodeException):
            await oauth2_factor.callback(
                code=None,
                state=state_token,
            )

    async def test_invalid_state_error(
        self, oauth2_factor: SQLAlchemyOAuth2Factor
    ) -> None:
        """Test that invalid state raises appropriate exception."""
        with pytest.raises(InvalidStateException):
            await oauth2_factor.callback(
                code="some-code",
                state="invalid-state-token",
            )

    async def test_creates_new_enrollment(
        self, oauth2_factor: SQLAlchemyOAuth2Factor
    ) -> None:
        """Test callback creates new enrollment when no existing one."""
        _, state_token, _ = await oauth2_factor.start(
            redirect_uri="https://example.com/callback",
            identity_id=123,
            scope=["read", "write"],
        )

        enrollment, account, returned_state = await oauth2_factor.callback(
            code="test-code",
            state=state_token,
        )

        assert enrollment is not None
        assert account is None
        assert isinstance(returned_state, OAuth2State)
        assert enrollment.identity_id == 123
        assert enrollment.provider == "provider"
        assert enrollment.account_id == "test-account-id"
        assert enrollment.access_token == "test-access-token"
        assert enrollment.scope == ["read", "write"]

    async def test_updates_existing_enrollment(
        self, oauth2_factor: SQLAlchemyOAuth2Factor
    ) -> None:
        """Test callback updates existing enrollment for same provider/account."""
        initial = OAuth2Enrollment(
            id=None,
            identity_id=456,
            provider="provider",
            account_id="test-account-id",
            access_token="old-token",
            expires_at=1000,
            refresh_token=None,
            refresh_token_expires_at=None,
            scope=["old_scope"],
        )
        initial.id = await oauth2_factor.insert(initial)

        _, state_token, _ = await oauth2_factor.start(
            redirect_uri="https://example.com/callback",
            scope=["new_scope"],
        )

        enrollment, account, returned_state = await oauth2_factor.callback(
            code="test-code",
            state=state_token,
        )

        assert enrollment is not None
        assert account is None
        assert isinstance(returned_state, OAuth2State)
        assert enrollment.id == initial.id
        assert enrollment.identity_id == 456
        assert enrollment.access_token == "test-access-token"
        assert enrollment.scope == ["new_scope"]

    async def test_identity_mismatch_error(
        self, oauth2_factor: SQLAlchemyOAuth2Factor
    ) -> None:
        """Test callback raises error when state identity doesn't match existing enrollment."""
        enrollment = OAuth2Enrollment(
            id=None,
            identity_id=789,
            provider="provider",
            account_id="test-account-id",
            access_token="old-token",
            expires_at=1000,
            refresh_token=None,
            refresh_token_expires_at=None,
            scope=[],
        )
        enrollment.id = await oauth2_factor.insert(enrollment)

        _, state_token, _ = await oauth2_factor.start(
            redirect_uri="https://example.com/callback",
            identity_id=999,
        )

        with pytest.raises(OAuth2IdentityMismatchException):
            await oauth2_factor.callback(
                code="test-code",
                state=state_token,
            )

    async def test_no_identity_returns_account(
        self, oauth2_factor: SQLAlchemyOAuth2Factor
    ) -> None:
        """Test callback returns (None, OAuth2Account) when no existing enrollment and no state identity."""
        _, state_token, _ = await oauth2_factor.start(
            redirect_uri="https://example.com/callback",
        )

        enrollment, account, returned_state = await oauth2_factor.callback(
            code="test-code",
            state=state_token,
        )

        assert enrollment is None
        assert isinstance(account, OAuth2Account)
        assert isinstance(returned_state, OAuth2State)
        assert account.provider == "provider"
        assert account.account_id == "test-account-id"
        assert account.access_token == "test-access-token"

    async def test_uses_existing_enrollment_identity(
        self, oauth2_factor: SQLAlchemyOAuth2Factor
    ) -> None:
        """Test callback uses existing enrollment's identity when state has no identity."""
        enrollment = OAuth2Enrollment(
            id=None,
            identity_id=111,
            provider="provider",
            account_id="test-account-id",
            access_token="old-token",
            expires_at=1000,
            refresh_token=None,
            refresh_token_expires_at=None,
            scope=[],
        )
        enrollment.id = await oauth2_factor.insert(enrollment)

        _, state_token, _ = await oauth2_factor.start(
            redirect_uri="https://example.com/callback",
        )

        enrollment, account, returned_state = await oauth2_factor.callback(
            code="test-code",
            state=state_token,
        )

        assert enrollment is not None
        assert account is None
        assert isinstance(returned_state, OAuth2State)
        assert enrollment.identity_id == 111

    async def test_uses_state_scope(
        self, oauth2_factor: SQLAlchemyOAuth2Factor
    ) -> None:
        """Test callback uses scope from state, not from exchange_code."""
        _, state_token, _ = await oauth2_factor.start(
            redirect_uri="https://example.com/callback",
            identity_id=222,
            scope=["state_scope"],
        )

        enrollment, account, returned_state = await oauth2_factor.callback(
            code="test-code",
            state=state_token,
        )

        assert enrollment is not None
        assert account is None
        assert isinstance(returned_state, OAuth2State)
        assert enrollment.scope == ["state_scope"]


@pytest.mark.anyio
class TestOAuth2FactorEnroll:
    """Test OAuth2 enroll functionality for signup flows."""

    async def test_enroll_creates_enrollment(
        self, oauth2_factor: SQLAlchemyOAuth2Factor
    ) -> None:
        """Test enroll creates a new enrollment from OAuth2Account."""
        oauth2_account = OAuth2Account(
            provider="provider",
            account_id="test-account-id",
            access_token="test-access-token",
            expires_at=3600,
            refresh_token="test-refresh-token",
            refresh_token_expires_at=7200,
            scope=["read", "write"],
        )

        enrollment = await oauth2_factor.enroll(
            identity_id=123,
            oauth2_account=oauth2_account,
        )

        assert isinstance(enrollment, OAuth2Enrollment)
        assert enrollment.id is not None
        assert enrollment.identity_id == 123
        assert enrollment.provider == "provider"
        assert enrollment.account_id == "test-account-id"
        assert enrollment.access_token == "test-access-token"
        assert enrollment.expires_at == 3600
        assert enrollment.refresh_token == "test-refresh-token"
        assert enrollment.refresh_token_expires_at == 7200
        assert enrollment.scope == ["read", "write"]


class TestTokenResponse:
    """Test TokenResponse dataclass functionality."""

    def test_account_id_string_unchanged(self) -> None:
        """Test that string account_id remains unchanged."""
        response = TokenResponse(
            account_id="test-account-id",
            access_token="test-token",
            expires_at=3600,
            refresh_token=None,
            refresh_token_expires_at=None,
        )
        assert response.account_id == "test-account-id"

    def test_account_id_integer_converted_to_string(self) -> None:
        """Test that integer account_id is converted to string."""
        import typing

        account_id_int: int = 12345
        response = TokenResponse(
            account_id=typing.cast(str, account_id_int),
            access_token="test-token",
            expires_at=3600,
            refresh_token=None,
            refresh_token_expires_at=None,
        )
        assert response.account_id == "12345"
        assert isinstance(response.account_id, str)
