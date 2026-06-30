import typing
import urllib.parse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from reauth.crypto import TokenHash
from reauth.factors.oauth2.base import OAuth2Enrollment, OAuth2TokenExchangeException
from reauth.factors.oauth2.microsoft import MicrosoftOAuth2Factor
from reauth.factors.oauth2.state import OAuth2State
from reauth.timestamp import get_current_timestamp

from .conftest import SQLAlchemyOAuth2StateService

TENANT_ID: typing.Final = "aaaabbbb-0000-cccc-1111-dddd2222eeee"
OTHER_TENANT_ID: typing.Final = "bbbbcccc-1111-dddd-2222-eeee3333ffff"
CLIENT_ID: typing.Final = "test-client-id"
CLIENT_SECRET: typing.Final = "test-client-secret"
KEY_ID: typing.Final = "test-key-1"
ACCESS_TOKEN: typing.Final = "test-access-token"
USERINFO_ENDPOINT: typing.Final = "https://graph.microsoft.com/oidc/userinfo"


def get_discovery_endpoint(tenant: str) -> str:
    return (
        f"https://login.microsoftonline.com/{tenant}/v2.0/"
        ".well-known/openid-configuration"
    )


def get_authorization_endpoint(tenant: str) -> str:
    return f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"


def get_token_endpoint(tenant: str) -> str:
    return f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"


def get_jwks_uri(tenant: str) -> str:
    return f"https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys"


def get_issuer(tenant_id: str = TENANT_ID) -> str:
    return f"https://login.microsoftonline.com/{tenant_id}/v2.0"


def get_jwks_data(
    key: RSAPrivateKey,
    *,
    issuer: str | None = "https://login.microsoftonline.com/{tenantid}/v2.0",
) -> dict[str, typing.Any]:
    algorithm = jwt.get_algorithm_by_name("RS256")
    jwk = {
        **algorithm.to_jwk(key.public_key(), as_dict=True),
        "kid": KEY_ID,
    }
    if issuer is not None:
        jwk["issuer"] = issuer
    return {"keys": [jwk]}


def create_id_token(
    key: RSAPrivateKey,
    *,
    issuer: str = get_issuer(),
    audience: str = CLIENT_ID,
    subject: str = "test-subject",
    tenant_id: str | None = TENANT_ID,
    nonce: str | None = None,
    expires_in: int = 3600,
    issued_at: int | None = None,
    key_id: str = KEY_ID,
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

    if tenant_id is not None:
        claims["tid"] = tenant_id
    if nonce is not None:
        claims["nonce"] = nonce

    return jwt.encode(
        claims,
        key,
        algorithm="RS256",
        headers={"kid": key_id, "alg": "RS256"},
    )


def get_token_response(
    key: RSAPrivateKey,
    *,
    issuer: str = get_issuer(),
    tenant_id: str | None = TENANT_ID,
    nonce: str | None = None,
) -> dict[str, typing.Any]:
    return {
        "access_token": ACCESS_TOKEN,
        "expires_in": 3600,
        "refresh_token": "test-refresh-token",
        "id_token": create_id_token(
            key,
            issuer=issuer,
            tenant_id=tenant_id,
            nonce=nonce,
        ),
    }


class MockMicrosoftOAuth2Factor(MicrosoftOAuth2Factor):
    def __init__(
        self,
        state_service: SQLAlchemyOAuth2StateService,
        key: RSAPrivateKey,
        *,
        tenant: str = "common",
        discovery_issuer: str = "https://login.microsoftonline.com/{tenantid}/v2.0",
        key_issuer: str | None = "https://login.microsoftonline.com/{tenantid}/v2.0",
        token_response: dict[str, typing.Any] | None = None,
    ) -> None:
        super().__init__(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            state_service=state_service,
            tenant=tenant,
        )
        self.key = key
        self.discovery_endpoint = get_discovery_endpoint(tenant)
        self.authorization_endpoint = get_authorization_endpoint(tenant)
        self.token_endpoint = get_token_endpoint(tenant)
        self.jwks_uri = get_jwks_uri(tenant)
        self.response_map = {
            self.discovery_endpoint: httpx.Response(
                200,
                json={
                    "authorization_endpoint": self.authorization_endpoint,
                    "token_endpoint": self.token_endpoint,
                    "jwks_uri": self.jwks_uri,
                    "issuer": discovery_issuer,
                    "userinfo_endpoint": USERINFO_ENDPOINT,
                    "id_token_signing_alg_values_supported": ["RS256"],
                    "token_endpoint_auth_methods_supported": ["client_secret_post"],
                },
            ),
            self.jwks_uri: httpx.Response(
                200,
                json=get_jwks_data(key, issuer=key_issuer),
            ),
            self.token_endpoint: httpx.Response(
                200,
                json=token_response or get_token_response(key),
            ),
            USERINFO_ENDPOINT: httpx.Response(
                200,
                json={
                    "sub": "test-subject",
                    "name": "Test User",
                    "email": "reauth@example.com",
                },
            ),
        }

    def _get_client(self) -> httpx.AsyncClient:
        def handle_request(request: httpx.Request) -> httpx.Response:
            return self.response_map.get(
                str(request.url), httpx.Response(404, json={"error": "not_found"})
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


@pytest.fixture(scope="module")
def rsa_key() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def oauth2_state() -> OAuth2State:
    return OAuth2State(
        id=None,
        state_hash=TokenHash("test-hash"),
        provider="microsoft",
        code_verifier=None,
        nonce=None,
        redirect_uri="https://redirect.example.com",
        identity_id=None,
        scope=None,
        expires_at=9999999999,
        context=None,
    )


@pytest.fixture
def microsoft_factor(
    oauth2_state_service: SQLAlchemyOAuth2StateService,
    rsa_key: RSAPrivateKey,
) -> MockMicrosoftOAuth2Factor:
    return MockMicrosoftOAuth2Factor(oauth2_state_service, rsa_key)


class TestMicrosoftOAuth2FactorInit:
    @pytest.mark.parametrize(
        "tenant",
        ["", " common", "common ", "common/path", "common?x=1", "common#frag"],
    )
    def test_rejects_invalid_tenant(
        self,
        rsa_key: RSAPrivateKey,
        tenant: str,
    ) -> None:
        state_service = typing.cast(SQLAlchemyOAuth2StateService, object())
        with pytest.raises(ValueError):
            MockMicrosoftOAuth2Factor(
                state_service,
                rsa_key,
                tenant=tenant,
            )


@pytest.mark.anyio
class TestMicrosoftOAuth2FactorGetAuthorizationURL:
    async def test_default_common_tenant_authorization_url(
        self, microsoft_factor: MockMicrosoftOAuth2Factor
    ) -> None:
        url = await microsoft_factor.get_authorization_url(
            redirect_uri="https://example.com/callback",
            scope=["User.Read"],
            state="test-state",
            code_challenge="test-challenge",
            code_challenge_method="S256",
            extra={"domain_hint": "organizations"},
        )

        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        assert url.startswith(f"{get_authorization_endpoint('common')}?")
        assert sorted(params["scope"][0].split()) == ["User.Read", "openid"]
        assert params["code_challenge"] == ["test-challenge"]
        assert params["code_challenge_method"] == ["S256"]
        assert params["domain_hint"] == ["organizations"]

    async def test_custom_tenant_authorization_url(
        self,
        oauth2_state_service: SQLAlchemyOAuth2StateService,
        rsa_key: RSAPrivateKey,
    ) -> None:
        factor = MockMicrosoftOAuth2Factor(
            oauth2_state_service,
            rsa_key,
            tenant=TENANT_ID,
            discovery_issuer=get_issuer(),
            key_issuer=get_issuer(),
            token_response=get_token_response(rsa_key, issuer=get_issuer()),
        )

        url = await factor.get_authorization_url(
            redirect_uri="https://example.com/callback",
            state="test-state",
        )

        assert url.startswith(f"{get_authorization_endpoint(TENANT_ID)}?")


@pytest.mark.anyio
class TestMicrosoftOAuth2FactorExchangeCode:
    async def test_successful_tenant_independent_exchange(
        self,
        microsoft_factor: MockMicrosoftOAuth2Factor,
        oauth2_state: OAuth2State,
    ) -> None:
        result = await microsoft_factor.exchange_code(
            code="test-code",
            redirect_uri="https://example.com/callback",
            state=oauth2_state,
        )

        assert result.account_id == f"{TENANT_ID}:test-subject"
        assert result.access_token == ACCESS_TOKEN
        assert result.refresh_token == "test-refresh-token"
        assert result.id_token is not None

    async def test_successful_tenant_specific_exchange(
        self,
        oauth2_state_service: SQLAlchemyOAuth2StateService,
        rsa_key: RSAPrivateKey,
        oauth2_state: OAuth2State,
    ) -> None:
        factor = MockMicrosoftOAuth2Factor(
            oauth2_state_service,
            rsa_key,
            tenant=TENANT_ID,
            discovery_issuer=get_issuer(),
            key_issuer=get_issuer(),
            token_response=get_token_response(rsa_key, issuer=get_issuer()),
        )

        result = await factor.exchange_code(
            code="test-code",
            redirect_uri="https://example.com/callback",
            state=oauth2_state,
        )

        assert result.account_id == f"{TENANT_ID}:test-subject"

    async def test_missing_tid_fails(
        self,
        oauth2_state_service: SQLAlchemyOAuth2StateService,
        rsa_key: RSAPrivateKey,
        oauth2_state: OAuth2State,
    ) -> None:
        factor = MockMicrosoftOAuth2Factor(
            oauth2_state_service,
            rsa_key,
            token_response=get_token_response(rsa_key, tenant_id=None),
        )

        with pytest.raises(OAuth2TokenExchangeException):
            await factor.exchange_code(
                code="test-code",
                redirect_uri="https://example.com/callback",
                state=oauth2_state,
            )

    async def test_invalid_tid_fails(
        self,
        oauth2_state_service: SQLAlchemyOAuth2StateService,
        rsa_key: RSAPrivateKey,
        oauth2_state: OAuth2State,
    ) -> None:
        factor = MockMicrosoftOAuth2Factor(
            oauth2_state_service,
            rsa_key,
            token_response=get_token_response(
                rsa_key,
                issuer="https://login.microsoftonline.com/not-a-guid/v2.0",
                tenant_id="not-a-guid",
            ),
        )

        with pytest.raises(OAuth2TokenExchangeException):
            await factor.exchange_code(
                code="test-code",
                redirect_uri="https://example.com/callback",
                state=oauth2_state,
            )

    async def test_issuer_mismatch_fails(
        self,
        oauth2_state_service: SQLAlchemyOAuth2StateService,
        rsa_key: RSAPrivateKey,
        oauth2_state: OAuth2State,
    ) -> None:
        factor = MockMicrosoftOAuth2Factor(
            oauth2_state_service,
            rsa_key,
            token_response=get_token_response(
                rsa_key,
                issuer=get_issuer(OTHER_TENANT_ID),
            ),
        )

        with pytest.raises(OAuth2TokenExchangeException):
            await factor.exchange_code(
                code="test-code",
                redirect_uri="https://example.com/callback",
                state=oauth2_state,
            )

    async def test_signing_key_issuer_mismatch_fails(
        self,
        oauth2_state_service: SQLAlchemyOAuth2StateService,
        rsa_key: RSAPrivateKey,
        oauth2_state: OAuth2State,
    ) -> None:
        factor = MockMicrosoftOAuth2Factor(
            oauth2_state_service,
            rsa_key,
            key_issuer=get_issuer(OTHER_TENANT_ID),
        )

        with pytest.raises(OAuth2TokenExchangeException):
            await factor.exchange_code(
                code="test-code",
                redirect_uri="https://example.com/callback",
                state=oauth2_state,
            )

    async def test_nonce_mismatch_fails(
        self,
        oauth2_state_service: SQLAlchemyOAuth2StateService,
        rsa_key: RSAPrivateKey,
        oauth2_state: OAuth2State,
    ) -> None:
        factor = MockMicrosoftOAuth2Factor(
            oauth2_state_service,
            rsa_key,
            token_response=get_token_response(rsa_key, nonce="actual-nonce"),
        )

        with pytest.raises(OAuth2TokenExchangeException):
            await factor.exchange_code(
                code="test-code",
                redirect_uri="https://example.com/callback",
                nonce="expected-nonce",
                state=oauth2_state,
            )

    async def test_bad_signature_fails(
        self,
        oauth2_state_service: SQLAlchemyOAuth2StateService,
        rsa_key: RSAPrivateKey,
        oauth2_state: OAuth2State,
    ) -> None:
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        factor = MockMicrosoftOAuth2Factor(
            oauth2_state_service,
            rsa_key,
            token_response=get_token_response(other_key),
        )

        with pytest.raises(OAuth2TokenExchangeException):
            await factor.exchange_code(
                code="test-code",
                redirect_uri="https://example.com/callback",
                state=oauth2_state,
            )


@pytest.mark.anyio
class TestMicrosoftOAuth2FactorGetProfile:
    async def test_get_profile_uses_discovered_userinfo_endpoint(
        self, microsoft_factor: MockMicrosoftOAuth2Factor
    ) -> None:
        profile = await microsoft_factor.get_profile(ACCESS_TOKEN)

        assert profile == {
            "sub": "test-subject",
            "name": "Test User",
            "email": "reauth@example.com",
        }
