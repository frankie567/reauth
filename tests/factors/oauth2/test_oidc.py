import base64
import secrets
import typing
import urllib.parse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from sqlalchemy.ext.asyncio import AsyncConnection

from reauth.crypto import TokenHash
from reauth.factors.oauth2.base import (
    OAuth2Enrollment,
    OAuth2InvalidClientException,
    OAuth2InvalidGrantException,
    OAuth2TokenExchangeException,
    OAuth2TokenInvalidRequestException,
    OAuth2TokenUnauthorizedClientException,
    OAuth2TokenUnsupportedGrantTypeException,
)
from reauth.factors.oauth2.oidc import (
    DiscoveryDocumentException,
    InvalidIDTokenException,
    JWKSFetchException,
    OIDCFactor,
    validate_id_token,
)
from reauth.factors.oauth2.state import OAuth2State
from reauth.timestamp import get_current_timestamp

from .conftest import SQLAlchemyOAuth2StateService


def generate_rsa_key() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def get_jwks_from_rsa_key(key: RSAPrivateKey, kid: str) -> jwt.PyJWKSet:
    algorithm = jwt.get_algorithm_by_name("RS256")
    public_jwk = {
        **algorithm.to_jwk(key.public_key(), as_dict=True),
        "kid": kid,
    }
    return jwt.PyJWKSet.from_dict({"keys": [public_jwk]})


def create_id_token(
    key: RSAPrivateKey,
    *,
    issuer: str = "https://issuer.example.com",
    audience: str = "test-client-id",
    subject: str = "test-user-id",
    nonce: str | None = None,
    access_token: str | None = None,
    expires_in: int = 3600,
    issued_at: int | None = None,
    key_id: str = "test-key-1",
) -> str:
    if issued_at is None:
        issued_at = get_current_timestamp()

    claims: dict[str, typing.Any] = {
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "exp": issued_at + expires_in,
        "iat": issued_at,
    }

    if nonce is not None:
        claims["nonce"] = nonce

    if access_token is not None:
        # Compute at_hash using the hash of the access_token
        # For RS256, we use SHA-256
        h = hashes.Hash(hashes.SHA256())
        h.update(access_token.encode())
        digest = h.finalize()
        at_hash = (
            base64.urlsafe_b64encode(digest[: len(digest) // 2]).rstrip(b"=").decode()
        )
        claims["at_hash"] = at_hash

    headers = {"kid": key_id, "alg": "RS256"}

    return jwt.encode(claims, key, algorithm="RS256", headers=headers)


DISCOVERY_ENDPOINT = "https://provider.example.com/.well-known/openid-configuration"
AUTHORIZATION_ENDPOINT = "https://provider.example.com/auth"
TOKEN_ENDPOINT = "https://provider.example.com/token"
JWKS_URI = "https://provider.example.com/jwks"
ISSUER = "https://provider.example.com"


def _create_token_response(
    key: RSAPrivateKey,
    *,
    client_id: str,
    access_token: str = "test-access-token",
    refresh_token: str = "test-refresh-token",
    nonce: str | None = None,
) -> dict[str, typing.Any]:
    """Create a test token response with a valid ID token."""
    id_token = create_id_token(
        key,
        issuer=ISSUER,
        audience=client_id,
        nonce=nonce,
        access_token=access_token,
    )
    return {
        "access_token": access_token,
        "expires_in": 3600,
        "refresh_token": refresh_token,
        "refresh_token_expires_in": 7200,
        "id_token": id_token,
    }


class SQLAlchemyOIDCFactor(OIDCFactor):
    """Concrete implementation of OIDCFactor using SQLAlchemy for testing."""

    DISCOVERY_ENDPOINT = DISCOVERY_ENDPOINT

    def __init__(
        self,
        connection: AsyncConnection,
        state_service: SQLAlchemyOAuth2StateService,
        key: RSAPrivateKey,
        token_endpoint_auth_methods_supported: list[str],
    ) -> None:
        super().__init__(
            identifier="oidc",
            client_id="test-client-id",
            client_secret="test-client-secret",
            state_service=state_service,
        )

        self.connection = connection
        algorithm = jwt.get_algorithm_by_name("RS256")
        jwk = {
            **algorithm.to_jwk(key.public_key(), as_dict=True),
            "kid": "test-key-1",
        }
        jwks = {"keys": [jwk]}

        self.response_map = {
            DISCOVERY_ENDPOINT: httpx.Response(
                200,
                json={
                    "authorization_endpoint": AUTHORIZATION_ENDPOINT,
                    "token_endpoint": TOKEN_ENDPOINT,
                    "jwks_uri": JWKS_URI,
                    "issuer": ISSUER,
                    "id_token_signing_alg_values_supported": ["RS256"],
                    "token_endpoint_auth_methods_supported": token_endpoint_auth_methods_supported,
                },
            ),
            JWKS_URI: httpx.Response(200, json=jwks),
            TOKEN_ENDPOINT: httpx.Response(
                200,
                json={
                    "access_token": "test-access-token",
                    "expires_in": 3600,
                    "refresh_token": "test-refresh-token",
                    "refresh_token_expires_in": 7200,
                    "id_token": create_id_token(
                        key,
                        issuer=ISSUER,
                        audience=self.client_id,
                        nonce="NONCE",
                        access_token="test-access-token",
                    ),
                },
            ),
        }

    def _get_client(self) -> httpx.AsyncClient:
        """Return an httpx.AsyncClient with MockTransport."""

        def handle_request(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            return self.response_map.get(
                url, httpx.Response(404, json={"error": "Not found"})
            )

        return httpx.AsyncClient(transport=httpx.MockTransport(handle_request))

    async def insert(self, enrollment: OAuth2Enrollment) -> int:
        raise NotImplementedError()

    async def update(self, enrollment: OAuth2Enrollment) -> None:
        raise NotImplementedError()

    async def get_enrollment(self, identity_id: int) -> OAuth2Enrollment | None:
        raise NotImplementedError()

    async def get_enrollment_by_provider_and_account(
        self, provider: str, account_id: str
    ) -> OAuth2Enrollment | None:
        raise NotImplementedError()

    async def get_id_token_claims(self, id_token: str) -> dict[str, typing.Any]:
        """Mock get_id_token_claims for testing - decodes without verification."""
        unverified = jwt.decode_complete(id_token, options={"verify_signature": False})
        return unverified["payload"]


@pytest.fixture(scope="module")
def oauth2_state() -> OAuth2State:
    """Return a mock OAuth2State for testing."""
    return OAuth2State(
        id=None,
        state_hash=TokenHash("test-hash"),
        provider="test",
        code_verifier=None,
        nonce=None,
        redirect_uri="https://redirect.example.com",
        identity_id=None,
        scope=None,
        expires_at=9999999999,
        context=None,
    )


@pytest.fixture(scope="module")
def rsa_key() -> RSAPrivateKey:
    return generate_rsa_key()


@pytest.fixture(scope="module")
def jwks(rsa_key: RSAPrivateKey) -> jwt.PyJWKSet:
    return get_jwks_from_rsa_key(rsa_key, "test-key-1")


@pytest.fixture(params=[["client_secret_basic"], ["client_secret_post"]])
def oidc_factor(
    request: pytest.FixtureRequest,
    sqlalchemy_connection: AsyncConnection,
    oauth2_state_service: SQLAlchemyOAuth2StateService,
    rsa_key: RSAPrivateKey,
) -> SQLAlchemyOIDCFactor:
    return SQLAlchemyOIDCFactor(
        sqlalchemy_connection, oauth2_state_service, rsa_key, request.param
    )


class TestValidateIDToken:
    """Tests for the main validate_id_token function."""

    def test_valid_token(self, rsa_key: RSAPrivateKey, jwks: jwt.PyJWKSet) -> None:
        """Test that a valid token passes all validations."""
        token = create_id_token(rsa_key)

        payload = validate_id_token(
            token,
            jwks,
            issuer="https://issuer.example.com",
            client_id="test-client-id",
            id_token_signing_alg_values_supported=["RS256"],
        )

        assert payload["sub"] == "test-user-id"
        assert payload["iss"] == "https://issuer.example.com"
        assert payload["aud"] == "test-client-id"

    def test_valid_token_with_nonce(
        self, rsa_key: RSAPrivateKey, jwks: jwt.PyJWKSet
    ) -> None:
        """Test that a valid token with nonce passes validation."""
        nonce = secrets.token_urlsafe(32)
        token = create_id_token(rsa_key, nonce=nonce)

        payload = validate_id_token(
            token,
            jwks,
            issuer="https://issuer.example.com",
            client_id="test-client-id",
            id_token_signing_alg_values_supported=["RS256"],
            nonce=nonce,
        )

        assert payload["nonce"] == nonce

    def test_valid_token_with_at_hash(
        self, rsa_key: RSAPrivateKey, jwks: jwt.PyJWKSet
    ) -> None:
        """Test that a valid token with at_hash passes validation."""
        access_token = secrets.token_urlsafe(32)
        token = create_id_token(rsa_key, access_token=access_token)

        payload = validate_id_token(
            token,
            jwks,
            issuer="https://issuer.example.com",
            client_id="test-client-id",
            id_token_signing_alg_values_supported=["RS256"],
            access_token=access_token,
        )

        assert payload["sub"] == "test-user-id"
        assert "at_hash" in payload

    def test_invalid_signature(self, rsa_key: RSAPrivateKey) -> None:
        """Test that an invalid signature raises InvalidIDTokenException."""
        token = create_id_token(rsa_key)

        # Create a different JWKS
        other_key = generate_rsa_key()
        other_jwks = get_jwks_from_rsa_key(other_key, "other-key")

        with pytest.raises(InvalidIDTokenException):
            validate_id_token(
                token,
                other_jwks,
                issuer="https://issuer.example.com",
                client_id="test-client-id",
                id_token_signing_alg_values_supported=["RS256"],
            )

    def test_mismatched_nonce(self, rsa_key: RSAPrivateKey, jwks: jwt.PyJWKSet) -> None:
        """Test that a mismatched nonce raises InvalidIDTokenException."""
        token = create_id_token(rsa_key, nonce="token-nonce")

        with pytest.raises(InvalidIDTokenException):
            validate_id_token(
                token,
                jwks,
                issuer="https://issuer.example.com",
                client_id="test-client-id",
                id_token_signing_alg_values_supported=["RS256"],
                nonce="expected-nonce",
            )

    def test_invalid_at_hash(self, rsa_key: RSAPrivateKey, jwks: jwt.PyJWKSet) -> None:
        """Test that an invalid at_hash raises InvalidIDTokenException."""
        access_token = secrets.token_urlsafe(32)
        token = create_id_token(
            rsa_key, key_id="test-key-1", access_token="invalid-access-token"
        )

        with pytest.raises(InvalidIDTokenException):
            validate_id_token(
                token,
                jwks,
                issuer="https://issuer.example.com",
                client_id="test-client-id",
                id_token_signing_alg_values_supported=["RS256"],
                access_token=access_token,
            )

    def test_expired_token(self, rsa_key: RSAPrivateKey, jwks: jwt.PyJWKSet) -> None:
        """Test that an expired token raises InvalidIDTokenException."""
        token = create_id_token(
            rsa_key, expires_in=1, issued_at=get_current_timestamp() - 3600
        )

        with pytest.raises(InvalidIDTokenException):
            validate_id_token(
                token,
                jwks,
                issuer="https://issuer.example.com",
                client_id="test-client-id",
                id_token_signing_alg_values_supported=["RS256"],
            )

    def test_wrong_audience(self, rsa_key: RSAPrivateKey, jwks: jwt.PyJWKSet) -> None:
        """Test that wrong audience raises InvalidIDTokenException."""
        token = create_id_token(rsa_key, audience="test-client-id")

        with pytest.raises(InvalidIDTokenException):
            validate_id_token(
                token,
                jwks,
                issuer="https://issuer.example.com",
                client_id="wrong-client-id",
                id_token_signing_alg_values_supported=["RS256"],
            )

    def test_wrong_issuer(self, rsa_key: RSAPrivateKey, jwks: jwt.PyJWKSet) -> None:
        """Test that wrong issuer raises InvalidIDTokenException."""
        token = create_id_token(rsa_key, issuer="https://issuer.example.com")

        with pytest.raises(InvalidIDTokenException):
            validate_id_token(
                token,
                jwks,
                issuer="https://wrong-issuer.example.com",
                client_id="test-client-id",
                id_token_signing_alg_values_supported=["RS256"],
            )


@pytest.mark.anyio
class TestOIDCFactorGetAuthorizationURL:
    """Tests for OIDCFactor.get_authorization_url()."""

    @pytest.mark.parametrize(
        "scope,expected_scopes",
        [
            ([], ["openid"]),
            (["profile"], ["openid", "profile"]),
            (["profile", "email"], ["openid", "profile", "email"]),
            (["openid"], ["openid"]),
            (["openid", "profile"], ["openid", "profile"]),
        ],
    )
    async def test_scope_includes_openid(
        self,
        oidc_factor: SQLAlchemyOIDCFactor,
        scope: list[str],
        expected_scopes: list[str],
    ) -> None:
        """Test that openid scope is automatically added."""
        url = await oidc_factor.get_authorization_url(
            redirect_uri="https://example.com/callback",
            scope=scope,
            state="test-state",
        )
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        actual_scopes = params.get("scope", [""])[0].split()
        assert sorted(actual_scopes) == sorted(expected_scopes)

    async def test_returns_authorization_endpoint_from_discovery(
        self, oidc_factor: SQLAlchemyOIDCFactor
    ) -> None:
        """Test that URL uses authorization_endpoint from discovery."""
        url = await oidc_factor.get_authorization_url(
            redirect_uri="https://example.com/callback",
            state="test-state",
        )
        assert url.startswith(f"{AUTHORIZATION_ENDPOINT}?")

    async def test_includes_required_params(
        self, oidc_factor: SQLAlchemyOIDCFactor
    ) -> None:
        """Test that required OAuth2 params are included."""
        url = await oidc_factor.get_authorization_url(
            redirect_uri="https://example.com/callback",
            state="test-state",
        )
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        assert params["response_type"] == ["code"]
        assert params["client_id"] == ["test-client-id"]
        assert "redirect_uri" in params
        assert params["state"] == ["test-state"]

    async def test_includes_pkce_params(
        self, oidc_factor: SQLAlchemyOIDCFactor
    ) -> None:
        """Test that PKCE params are included when provided."""
        url = await oidc_factor.get_authorization_url(
            redirect_uri="https://example.com/callback",
            state="test-state",
            code_challenge="test-challenge",
            code_challenge_method="S256",
        )
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        assert params["code_challenge"] == ["test-challenge"]
        assert params["code_challenge_method"] == ["S256"]

    async def test_includes_nonce(self, oidc_factor: SQLAlchemyOIDCFactor) -> None:
        """Test that nonce is included when provided."""
        url = await oidc_factor.get_authorization_url(
            redirect_uri="https://example.com/callback",
            state="test-state",
            nonce="test-nonce",
        )
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        assert params["nonce"] == ["test-nonce"]

    async def test_includes_extra_params(
        self, oidc_factor: SQLAlchemyOIDCFactor
    ) -> None:
        """Test that extra OIDC params are included."""
        url = await oidc_factor.get_authorization_url(
            redirect_uri="https://example.com/callback",
            state="test-state",
            extra={"prompt": "login", "login_hint": "reauth@example.com"},
        )
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        assert params["prompt"] == ["login"]
        assert params["login_hint"] == ["reauth@example.com"]


@pytest.mark.anyio
class TestOIDCFactorExchangeCode:
    """Tests for OIDCFactor.exchange_code()."""

    async def test_successful_exchange(
        self, oidc_factor: SQLAlchemyOIDCFactor, oauth2_state: OAuth2State
    ) -> None:
        """Test successful token exchange returns correct data."""
        result = await oidc_factor.exchange_code(
            code="test-code",
            redirect_uri="https://example.com/callback",
            state=oauth2_state,
        )

        assert result.account_id == "test-user-id"
        assert result.access_token == "test-access-token"
        assert result.expires_at > 0
        assert result.refresh_token == "test-refresh-token"
        assert result.refresh_token_expires_at is not None
        assert result.refresh_token_expires_at > 0
        assert result.id_token is not None

    async def test_discovery_document_error(
        self, oidc_factor: SQLAlchemyOIDCFactor, oauth2_state: OAuth2State
    ) -> None:
        """Test DiscoveryDocumentException when discovery endpoint fails."""
        oidc_factor.response_map[DISCOVERY_ENDPOINT] = httpx.Response(
            500, json={"error": "Server error"}
        )
        with pytest.raises(DiscoveryDocumentException):
            await oidc_factor.exchange_code(
                code="test-code",
                redirect_uri="https://example.com/callback",
                state=oauth2_state,
            )

    async def test_jwks_error(
        self, oidc_factor: SQLAlchemyOIDCFactor, oauth2_state: OAuth2State
    ) -> None:
        """Test DiscoveryDocumentException when JWKS endpoint fails."""
        oidc_factor.response_map[JWKS_URI] = httpx.Response(
            500, json={"error": "Server error"}
        )
        with pytest.raises(JWKSFetchException):
            await oidc_factor.exchange_code(
                code="test-code",
                redirect_uri="https://example.com/callback",
                state=oauth2_state,
            )

    async def test_server_error_on_token_exchange(
        self, oidc_factor: SQLAlchemyOIDCFactor, oauth2_state: OAuth2State
    ) -> None:
        """Test OAuth2TokenExchangeException on server error."""
        oidc_factor.response_map[TOKEN_ENDPOINT] = httpx.Response(
            500, json={"error": "Server error"}
        )
        with pytest.raises(OAuth2TokenExchangeException):
            await oidc_factor.exchange_code(
                code="test-code",
                redirect_uri="https://example.com/callback",
                state=oauth2_state,
            )

    @pytest.mark.parametrize(
        "error,expected_exception",
        [
            ("invalid_request", OAuth2TokenInvalidRequestException),
            ("invalid_client", OAuth2InvalidClientException),
            ("invalid_grant", OAuth2InvalidGrantException),
            ("unauthorized_client", OAuth2TokenUnauthorizedClientException),
            ("unsupported_grant_type", OAuth2TokenUnsupportedGrantTypeException),
        ],
    )
    async def test_rfc6749_token_errors(
        self,
        oidc_factor: SQLAlchemyOIDCFactor,
        oauth2_state: OAuth2State,
        error: str,
        expected_exception: type[Exception],
    ) -> None:
        """Test that RFC 6749 token errors are properly mapped."""
        oidc_factor.response_map[TOKEN_ENDPOINT] = httpx.Response(
            400, json={"error": error, "error_description": "Test error"}
        )
        with pytest.raises(expected_exception):
            await oidc_factor.exchange_code(
                code="test-code",
                redirect_uri="https://example.com/callback",
                state=oauth2_state,
            )
