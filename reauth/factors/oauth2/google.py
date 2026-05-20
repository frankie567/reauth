import abc

from reauth.factors.oauth2.oidc import OIDCFactor
from reauth.factors.oauth2.state import OAuth2StateService


class GoogleOAuth2Factor(OIDCFactor, abc.ABC):
    """
    Google OAuth2 factor implementation, using the OpenID Connect protocol.

    References:
        - Google: https://developers.google.com/identity/openid-connect/openid-connect
    """

    DISCOVERY_ENDPOINT = "https://accounts.google.com/.well-known/openid-configuration"

    def __init__(
        self,
        *,
        identifier: str = "google",
        client_id: str,
        client_secret: str,
        state_service: OAuth2StateService,
        step: int = 0,
    ) -> None:
        super().__init__(
            identifier=identifier,
            step=step,
            client_id=client_id,
            client_secret=client_secret,
            state_service=state_service,
        )
