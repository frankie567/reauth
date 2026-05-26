import abc
import base64
import hmac
import typing
import urllib.parse

import httpx
import jwt

from reauth.factors.oauth2.base import (
    RFC_6749_TOKEN_ERROR_MAP,
    OAuth2Exception,
    OAuth2Factor,
    OAuth2GetProfileException,
    OAuth2TokenExchangeException,
    TokenResponse,
)
from reauth.factors.oauth2.pkce import CodeChallengeMethod
from reauth.factors.oauth2.state import OAuth2State, OAuth2StateService
from reauth.logging import get_logger
from reauth.timestamp import get_current_timestamp

logger = get_logger(__name__)


class OIDCException(OAuth2Exception):
    """Base exception for OpenID Connect errors."""


class DiscoveryDocumentException(OIDCException):
    """Raised when there is an error fetching or parsing the OpenID Connect discovery document."""


class JWKSFetchException(OIDCException):
    """Raised when there is an error fetching the JWKS for ID Token validation."""


class InvalidIDTokenException(OIDCException):
    """Raised when an ID Token fails validation."""


def _validate_id_token_signature(
    id_token: str,
    jwk: jwt.PyJWK,
    *,
    algorithms: list[str],
    audience: str,
    issuer: str,
) -> dict[str, typing.Any]:
    """Validate an ID Token's signature and standard claims.

    Validates:
    - JWT structure (3 parts)
    - Required claims: iss, sub, aud, exp, iat
    - Signature verification
    - Audience matches expected audience
    - Issuer matches expected issuer
    - Token not expired

    Args:
        id_token: The ID Token JWT string.
        jwk: The JWK to use for signature verification.
        algorithms: List of allowed signing algorithms.
        audience: Expected audience (client_id).
        issuer: Expected issuer.

    Returns:
        The decoded payload as a dictionary.

    Raises:
        InvalidIDTokenException: If the token signature or claims are invalid.
    """
    try:
        decoded = jwt.decode_complete(
            id_token,
            jwk,
            algorithms=algorithms,
            audience=audience,
            issuer=issuer,
            options={
                "verify_exp": True,
                "verify_iat": True,
                "verify_aud": True,
                "verify_iss": True,
                "require": ["exp", "iat", "sub"],
            },
        )
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError) as e:
        raise InvalidIDTokenException() from e

    return decoded["payload"]


def _validate_id_token_nonce(
    payload: dict[str, typing.Any],
    expected_nonce: str | None,
) -> None:
    """Validate the nonce claim in an ID Token payload.

    Args:
        payload: The decoded ID Token payload.
        expected_nonce: The expected nonce value.

    Raises:
        InvalidIDTokenException: If the nonce does not match.
    """
    if expected_nonce is not None and payload.get("nonce") != expected_nonce:
        raise InvalidIDTokenException()


def _validate_id_token_at_hash(
    payload: dict[str, typing.Any],
    header: dict[str, typing.Any],
    access_token: str,
) -> None:
    """Validate the at_hash claim in an ID Token payload.

    The at_hash is computed as:
    base64url encode of the first half of the hash of the access_token.

    Args:
        payload: The decoded ID Token payload.
        header: The JWT header containing the algorithm.
        access_token: The access token to hash.

    Raises:
        InvalidIDTokenException: If the at_hash does not match.
    """
    if "at_hash" not in payload:  # pragma: no cover
        return

    alg = jwt.get_algorithm_by_name(header["alg"])
    digest = alg.compute_hash_digest(access_token.encode())
    computed_at_hash = base64.urlsafe_b64encode(digest[: (len(digest) // 2)]).rstrip(
        b"="
    )
    if not hmac.compare_digest(computed_at_hash, payload["at_hash"].encode()):
        raise InvalidIDTokenException()


def validate_id_token(
    id_token: str,
    jwks: jwt.PyJWKSet,
    *,
    issuer: str,
    client_id: str,
    id_token_signing_alg_values_supported: list[str],
    nonce: str | None = None,
    access_token: str | None = None,
) -> dict[str, typing.Any]:
    """Validate an OpenID Connect ID Token.

    This is a synchronous function that validates all aspects of an ID Token.
    All required data (discovery document info, JWKS) must be passed as arguments.

    Validates:
    - JWT structure (3 parts)
    - Required claims: iss, sub, aud, exp, iat
    - Signature (using the JWK from JWKS matching the kid in the header)
    - Nonce (if provided)
    - at_hash (if access_token provided)
    - Audience matches expected audience
    - Issuer matches expected issuer
    - Token not expired

    Args:
        id_token: The ID Token JWT string.
        jwks: The JWKS containing the signing keys.
        issuer: The expected issuer from the discovery document.
        client_id: The expected audience (client_id).
        id_token_signing_alg_values_supported: List of supported signing algorithms.
        nonce: Expected nonce value for replay attack protection (optional).
        access_token: Access token for at_hash validation (optional).

    Returns:
        The decoded payload as a dictionary.

    Raises:
        InvalidIDTokenException: If the token is invalid.
    """
    # First, decode without verification to get the header and kid
    unverified = jwt.decode_complete(id_token, options={"verify_signature": False})
    header = unverified["header"]

    # Get the JWK for this kid
    try:
        jwk = jwks[header["kid"]]
    except KeyError as e:
        raise InvalidIDTokenException() from e

    # Validate signature and standard claims
    payload = _validate_id_token_signature(
        id_token,
        jwk,
        algorithms=id_token_signing_alg_values_supported,
        audience=client_id,
        issuer=issuer,
    )

    # Validate nonce
    _validate_id_token_nonce(payload, nonce)

    # Validate at_hash
    if access_token is not None:
        _validate_id_token_at_hash(payload, unverified["header"], access_token)

    return payload


class OIDCExtraParams(typing.TypedDict, total=False):
    """
    Extra parameters for OpenID Connect authorization URL.

    References:
        - OpenID Connect Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
    """

    scope: str
    response_type: typing.Literal[
        "code", "id_token", "code id_token", "code token", "id_token token"
    ]
    nonce: str
    display: typing.Literal["page", "popup", "touch", "wap"]
    prompt: typing.Literal["none", "login", "consent", "select_account"]
    max_age: int
    ui_locales: str
    id_token_hint: str
    login_hint: str
    acr_values: str
    response_mode: typing.Literal["query", "fragment", "form_post"]


class OIDCFactorBase(OAuth2Factor[OIDCExtraParams], abc.ABC):
    """Base OpenID Connect factor implementation.

    This class implements the core OIDC flow using the discovery document
    and JWKS for ID Token validation.

    Subclasses must implement `get_client_secret()` to provide the client secret
    for token exchange. For cases where the client secret is static and known
    at instantiation, use the `OIDCFactor` subclass which provides a default
    implementation.

    References:
        - OpenID Connect Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
    """

    DISCOVERY_ENDPOINT: typing.ClassVar[str]

    def __init__(
        self,
        *,
        identifier: str,
        client_id: str,
        state_service: OAuth2StateService,
        step: int = 0,
    ) -> None:
        super().__init__(
            identifier=identifier,
            step=step,
            client_id=client_id,
            state_service=state_service,
        )
        self._discovery_document: dict[str, typing.Any] | None = None
        self._jwks: jwt.PyJWKSet | None = None
        self._client = httpx.AsyncClient()

    async def get_authorization_url(
        self,
        *,
        redirect_uri: str,
        scope: list[str] | None = None,
        state: str,
        code_challenge: str | None = None,
        code_challenge_method: CodeChallengeMethod | None = None,
        nonce: str | None = None,
        extra: OIDCExtraParams | None = None,
    ) -> str:
        logger.debug(
            "OIDC get_authorization_url called", extra={"provider": self.identifier}
        )
        scope = scope or []
        if "openid" not in scope:
            scope.append("openid")

        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(scope),
        }

        if state is not None:
            params["state"] = state

        if code_challenge is not None:
            params["code_challenge"] = code_challenge

        if code_challenge_method is not None:
            params["code_challenge_method"] = code_challenge_method

        if nonce is not None:
            params["nonce"] = nonce

        if extra is not None:
            params = {**params, **extra}

        discovery_document = await self._get_discovery_document()
        authorize_endpoint = discovery_document["authorization_endpoint"]
        return f"{authorize_endpoint}?{urllib.parse.urlencode(params)}"

    async def exchange_code(
        self,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str | None = None,
        nonce: str | None = None,
        state: OAuth2State,
    ) -> TokenResponse:
        logger.debug("OIDC exchange_code called", extra={"provider": self.identifier})
        discovery_document = await self._get_discovery_document()
        token_endpoint = discovery_document["token_endpoint"]
        token_endpoint_auth_methods_supported = discovery_document.get(
            "token_endpoint_auth_methods_supported", ["client_secret_basic"]
        )

        auth: httpx.BasicAuth | None = None
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
        }
        client_secret = await self.get_client_secret()
        if "client_secret_post" in token_endpoint_auth_methods_supported:
            data = {
                **data,
                "client_id": self.client_id,
                "client_secret": client_secret,
            }
        elif "client_secret_basic" in token_endpoint_auth_methods_supported:
            auth = httpx.BasicAuth(self.client_id, client_secret)

        client = self._get_client()
        if code_verifier is not None:
            data["code_verifier"] = code_verifier

        try:
            response = await client.post(
                token_endpoint,
                data=data,
                auth=auth if auth else httpx.USE_CLIENT_DEFAULT,
            )
        except httpx.RequestError as e:
            raise OAuth2TokenExchangeException(state=state) from e

        if response.is_server_error:
            raise OAuth2TokenExchangeException(state=state)

        if response.is_client_error:
            json = response.json()
            try:
                error = json.get("error")
                error_type = RFC_6749_TOKEN_ERROR_MAP[error]
                raise error_type(
                    error_description=json.get("error_description"),
                    error_uri=json.get("error_uri"),
                    state=state,
                )
            except KeyError as e:
                raise OAuth2TokenExchangeException(state=state) from e

        if response.is_success:
            json = response.json()
            access_token = json["access_token"]
            expires_at = get_current_timestamp() + json["expires_in"]

            refresh_token: str | None = None
            refresh_token_expires_at: int | None = None
            if "refresh_token" in json:
                refresh_token = json["refresh_token"]
            if "refresh_token_expires_in" in json:
                refresh_token_expires_at = (
                    get_current_timestamp() + json["refresh_token_expires_in"]
                )

            id_token = json["id_token"]
            try:
                id_token_payload = await self._validate_id_token(
                    id_token, nonce=nonce, access_token=access_token
                )
            except InvalidIDTokenException as e:
                raise OAuth2TokenExchangeException(state=state) from e
            account_id = id_token_payload["sub"]

            return TokenResponse(
                account_id=account_id,
                access_token=access_token,
                expires_at=expires_at,
                refresh_token=refresh_token,
                refresh_token_expires_at=refresh_token_expires_at,
                id_token=id_token,
            )

        raise OAuth2TokenExchangeException(state=state)

    async def get_id_token_claims(self, id_token: str) -> dict[str, typing.Any]:
        """Decode and return claims from an ID Token JWT.

        This method validates and decodes the id_token JWT, returning the claims.
        It's intended for providers like Apple that don't support userinfo endpoint.

        Args:
            id_token: The OIDC ID Token JWT string.

        Returns:
            dict[str, Any]: The decoded JWT claims/payload.
        """
        logger.debug(
            "OIDC get_id_token_claims called", extra={"provider": self.identifier}
        )
        return await self._validate_id_token(id_token)

    async def get_profile(self, access_token: str) -> dict[str, typing.Any]:
        """Get identity claims from provider via userinfo endpoint.

        For OIDC providers that support the userinfo endpoint.

        Args:
            access_token: The OAuth2 access token for making authenticated requests.

        Returns:
            dict[str, Any]: Provider-specific profile claims.

        Raises:
            NotImplementedError: If provider has no userinfo endpoint.
            OAuth2GetProfileException: If fetching the profile fails.
        """
        logger.debug("OIDC get_profile called", extra={"provider": self.identifier})

        discovery_document = await self._get_discovery_document()
        userinfo_endpoint = discovery_document.get("userinfo_endpoint")

        if userinfo_endpoint is None:
            raise NotImplementedError("Provider has no userinfo endpoint")

        try:
            client = self._get_client()
            response = await client.get(
                userinfo_endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            raise OAuth2GetProfileException() from e

    async def _validate_id_token(
        self,
        id_token: str,
        *,
        nonce: str | None = None,
        access_token: str | None = None,
    ) -> dict[str, typing.Any]:
        """Validate an OpenID Connect ID Token.

        Validates:
        - JWT structure (3 parts)
        - Required claims: iss, sub, aud, exp, iat
        - Signature (if secret/key is available)
        - Nonce (if provided)
        - at_hash (if access_token provided)
        - Audience matches expected audience
        - Issuer matches expected issuer
        - Token not expired

        Args:
            id_token: The ID Token JWT string.
            nonce: Expected nonce value for replay attack protection.
            access_token: Access token for at_hash validation.

        Returns:
            The decoded payload as a dictionary.

        Raises:
            InvalidIDTokenException: If the token is invalid.
        """  # noqa: DOC502
        discovery_document = await self._get_discovery_document()
        issuer = discovery_document["issuer"]
        id_token_signing_alg_values_supported = discovery_document[
            "id_token_signing_alg_values_supported"
        ]
        jwks = await self._get_jwks()
        return validate_id_token(
            id_token,
            jwks,
            issuer=issuer,
            client_id=self.client_id,
            id_token_signing_alg_values_supported=id_token_signing_alg_values_supported,
            nonce=nonce,
            access_token=access_token,
        )

    async def _get_discovery_document(self) -> dict[str, typing.Any]:
        if self._discovery_document is not None:  # pragma: no cover
            return self._discovery_document

        client = self._get_client()
        try:
            response = await client.get(self.DISCOVERY_ENDPOINT)
            response.raise_for_status()
        except httpx.HTTPError as e:
            raise DiscoveryDocumentException() from e
        else:
            discovery_document = response.json()
            self._discovery_document = discovery_document
            return discovery_document

    async def _get_jwks(self) -> jwt.PyJWKSet:
        if self._jwks is not None:  # pragma: no cover
            return self._jwks

        discovery_document = await self._get_discovery_document()
        client = self._get_client()
        try:
            response = await client.get(discovery_document["jwks_uri"])
            response.raise_for_status()
        except httpx.HTTPError as e:
            raise JWKSFetchException() from e
        else:
            jwks_data = response.json()
            jwks = jwt.PyJWKSet.from_dict(jwks_data)
            self._jwks = jwks
            return jwks

    def _get_client(self) -> httpx.AsyncClient:  # pragma: no cover
        return self._client


class OIDCFactor(OIDCFactorBase):
    """OpenID Connect factor implementation with a static client secret.

    This class provides a default implementation of `get_client_secret()` that returns
    a fixed client secret provided at instantiation. Use this for most OAuth providers.

    For providers requiring dynamic client secrets (e.g., Apple Sign In),
    subclass `OIDCFactorBase` directly and override `get_client_secret()`.
    """

    def __init__(
        self,
        *,
        identifier: str,
        client_id: str,
        client_secret: str,
        state_service: OAuth2StateService,
        step: int = 0,
    ) -> None:
        super().__init__(
            identifier=identifier,
            client_id=client_id,
            state_service=state_service,
            step=step,
        )
        self._client_secret = client_secret

    async def get_client_secret(self) -> str:
        return self._client_secret
