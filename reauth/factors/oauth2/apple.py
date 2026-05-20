import abc
import time

import jwt

from reauth.factors.oauth2.oidc import OIDCFactorBase
from reauth.factors.oauth2.state import OAuth2StateService


class AppleOAuth2Factor(OIDCFactorBase, abc.ABC):
    """Apple OAuth2 factor implementation using OpenID Connect.

    Unlike most OAuth providers, Apple requires a dynamic client secret generated
    as a JWT and signed with your private key for each authorization request.
    This implementation generates the client secret on-demand using ES256.

    References:
        - Apple: https://developer.apple.com/documentation/accountorganizationaldatasharing/creating-a-client-secret
    """

    DISCOVERY_ENDPOINT = "https://appleid.apple.com/.well-known/openid-configuration"

    def __init__(
        self,
        *,
        identifier: str = "apple",
        client_id: str,
        team_id: str,
        key_id: str,
        key_value: str,
        state_service: OAuth2StateService,
        step: int = 0,
    ) -> None:
        super().__init__(
            identifier=identifier,
            step=step,
            client_id=client_id,
            state_service=state_service,
        )
        self.team_id = team_id
        self.key_id = key_id
        self.key_value = key_value

    async def get_client_secret(self) -> str:
        """Generate a JWT client secret for Apple's OAuth2 token exchange.

        Creates a signed JWT containing the team ID, client ID, and expiration time.
        The JWT is signed with the ES256 algorithm using the private key provided
        during initialization.

        Returns:
            A JWT string to be used as the client secret.
        """
        iat = int(time.time())
        client_secret = jwt.encode(
            {
                "iss": self.team_id,
                "aud": "https://appleid.apple.com",
                "sub": self.client_id,
                "iat": iat,
                "exp": iat + 3600,
            },
            self.key_value,
            algorithm="ES256",
            headers={
                "kid": self.key_id,
            },
        )
        return client_secret
