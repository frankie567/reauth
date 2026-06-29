import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from reauth.factors.oauth2.apple import AppleOAuth2Factor
from reauth.factors.oauth2.base import OAuth2Enrollment

from .conftest import SQLAlchemyOAuth2StateService


def _generate_ec_key() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


class _AppleFactor(AppleOAuth2Factor):
    async def insert(self, enrollment: OAuth2Enrollment) -> int:
        raise NotImplementedError()

    async def update(self, enrollment: OAuth2Enrollment) -> None:
        raise NotImplementedError()

    async def get_enrollment_by_provider_and_account(
        self, provider: str, account_id: str
    ) -> OAuth2Enrollment | None:
        raise NotImplementedError()

    async def get_enrollment(self, identity_id: int) -> OAuth2Enrollment | None:
        raise NotImplementedError()


@pytest.mark.anyio
class TestAppleFactorGetRequestAuthentication:
    """Tests for AppleOAuth2Factor.get_request_authentication()."""

    async def test_returns_signed_jwt_client_secret(
        self, oauth2_state_service: SQLAlchemyOAuth2StateService
    ) -> None:
        """Apple authenticates with a per-request ES256 JWT in the request body."""
        factor = _AppleFactor(
            client_id="com.example.app",
            team_id="TEAM123456",
            key_id="KEY123456",
            key_value=_generate_ec_key(),
            state_service=oauth2_state_service,
        )

        headers, body = await factor.get_request_authentication(
            token_endpoint="https://appleid.apple.com/auth/token"
        )

        assert headers == {}
        assert body["client_id"] == "com.example.app"
        claims = jwt.decode(body["client_secret"], options={"verify_signature": False})
        assert claims["iss"] == "TEAM123456"
        assert claims["sub"] == "com.example.app"
        assert claims["aud"] == "https://appleid.apple.com"
