import abc
import typing
import urllib.parse
import uuid

import httpx
import jwt

from reauth.factors.oauth2.oidc import (
    InvalidIDTokenException,
    JWKSFetchException,
    OIDCFactor,
    validate_id_token,
)
from reauth.factors.oauth2.state import OAuth2StateService


class MicrosoftOAuth2Factor(OIDCFactor, abc.ABC):
    """
    Microsoft OAuth2 factor implementation, using the OpenID Connect protocol.

    References:
        - Microsoft: https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc
    """

    DISCOVERY_ENDPOINT = (
        "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration"
    )

    def __init__(
        self,
        *,
        identifier: str = "microsoft",
        client_id: str,
        client_secret: str,
        state_service: OAuth2StateService,
        tenant: str = "common",
        step: int = 0,
    ) -> None:
        super().__init__(
            identifier=identifier,
            step=step,
            client_id=client_id,
            client_secret=client_secret,
            state_service=state_service,
        )
        self.tenant = self._validate_tenant(tenant)
        self._jwks_document: dict[str, typing.Any] | None = None

    def _get_discovery_endpoint(self) -> str:
        return (
            f"https://login.microsoftonline.com/{self.tenant}/v2.0/"
            ".well-known/openid-configuration"
        )

    async def _validate_id_token(
        self,
        id_token: str,
        *,
        nonce: str | None = None,
        access_token: str | None = None,
    ) -> dict[str, typing.Any]:
        discovery_document = await self._get_discovery_document()
        jwks_document = await self._get_jwks_document()
        jwks = await self._get_jwks()
        unverified = self._decode_unverified_id_token(id_token)
        payload = unverified["payload"]
        issuer = self._get_expected_issuer(discovery_document["issuer"], payload)
        self._validate_jwk_issuer(jwks_document, unverified["header"], issuer, payload)
        return validate_id_token(
            id_token,
            jwks,
            issuer=issuer,
            client_id=self.client_id,
            id_token_signing_alg_values_supported=discovery_document[
                "id_token_signing_alg_values_supported"
            ],
            nonce=nonce,
            access_token=access_token,
        )

    def _get_account_id(self, id_token_payload: dict[str, typing.Any]) -> str:
        if not isinstance(subject := id_token_payload.get("sub"), str):
            raise InvalidIDTokenException()
        if not isinstance(tenant_id := id_token_payload.get("tid"), str):
            raise InvalidIDTokenException()
        self._validate_tenant_id(tenant_id)
        return f"{tenant_id}:{subject}"

    @staticmethod
    def _validate_tenant(tenant: str) -> str:
        if not tenant or tenant.strip() != tenant:
            raise ValueError()

        parsed = urllib.parse.urlsplit(tenant)
        if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
            raise ValueError()
        if "/" in tenant:
            raise ValueError()

        return tenant

    @staticmethod
    def _decode_unverified_id_token(id_token: str) -> dict[str, typing.Any]:
        try:
            return jwt.decode_complete(id_token, options={"verify_signature": False})
        except jwt.InvalidTokenError as e:
            raise InvalidIDTokenException() from e

    @classmethod
    def _get_expected_issuer(
        cls,
        discovery_issuer: str,
        payload: dict[str, typing.Any],
    ) -> str:
        if "{tenantid}" not in discovery_issuer:
            return discovery_issuer

        if not isinstance(tenant_id := payload.get("tid"), str):
            raise InvalidIDTokenException()

        cls._validate_tenant_id(tenant_id)
        return discovery_issuer.replace("{tenantid}", tenant_id)

    async def _get_jwks(self) -> jwt.PyJWKSet:
        if self._jwks is not None:  # pragma: no cover
            return self._jwks

        jwks_document = await self._get_jwks_document()
        jwks = jwt.PyJWKSet.from_dict(jwks_document)
        self._jwks = jwks
        return jwks

    async def _get_jwks_document(self) -> dict[str, typing.Any]:
        if self._jwks_document is not None:  # pragma: no cover
            return self._jwks_document

        discovery_document = await self._get_discovery_document()
        client = self._get_client()
        try:
            response = await client.get(discovery_document["jwks_uri"])
            response.raise_for_status()
        except httpx.HTTPError as e:
            raise JWKSFetchException() from e
        else:
            jwks_document = response.json()
            self._jwks_document = jwks_document
            return jwks_document

    @classmethod
    def _validate_jwk_issuer(
        cls,
        jwks_document: dict[str, typing.Any],
        header: dict[str, typing.Any],
        expected_issuer: str,
        payload: dict[str, typing.Any],
    ) -> None:
        key = cls._get_jwk_data(jwks_document, header)
        if (jwk_issuer := key.get("issuer")) is None:
            return
        if not isinstance(jwk_issuer, str):
            raise InvalidIDTokenException()
        if jwk_issuer == expected_issuer:
            return
        if "{tenantid}" in jwk_issuer and isinstance(
            tenant_id := payload.get("tid"), str
        ):
            cls._validate_tenant_id(tenant_id)
            if jwk_issuer.replace("{tenantid}", tenant_id) == expected_issuer:
                return

        raise InvalidIDTokenException()

    @staticmethod
    def _get_jwk_data(
        jwks_document: dict[str, typing.Any],
        header: dict[str, typing.Any],
    ) -> dict[str, typing.Any]:
        try:
            key_id = header["kid"]
            keys = jwks_document["keys"]
        except KeyError as e:
            raise InvalidIDTokenException() from e

        if not isinstance(key_id, str) or not isinstance(keys, list):
            raise InvalidIDTokenException()

        for key in keys:
            if isinstance(key, dict) and key.get("kid") == key_id:
                return key

        raise InvalidIDTokenException()

    @staticmethod
    def _validate_tenant_id(tenant_id: str) -> None:
        try:
            parsed = uuid.UUID(tenant_id)
        except ValueError as e:
            raise InvalidIDTokenException() from e

        if str(parsed) != tenant_id.lower():
            raise InvalidIDTokenException()
