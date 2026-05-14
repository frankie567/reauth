import abc
import dataclasses
import typing

from reauth.exceptions import ReauthException
from reauth.logging import get_logger

from ...amr import AuthenticationMethodReference
from ..base import FactorBase
from .pkce import CodeChallengeMethod, generate_code_challenge, generate_code_verifier
from .state import OAuth2StateService

logger = get_logger(__name__)


@dataclasses.dataclass
class OAuth2Enrollment:
    id: typing.Any | None
    identity_id: typing.Any
    provider: str
    account_id: str
    access_token: str
    expires_at: int | None
    refresh_token: str | None
    refresh_token_expires_at: int | None
    scope: list[str]


class OAuth2Exception(ReauthException):
    """Base exception for OAuth2 errors."""


class OAuth2Factor(FactorBase[OAuth2Enrollment], abc.ABC):
    AMR: typing.ClassVar[AuthenticationMethodReference] = (
        AuthenticationMethodReference.OAUTH2
    )

    def __init__(
        self,
        *,
        identifier: str,
        client_id: str,
        state_service: OAuth2StateService,
        min_prior_factors: int = 0,
    ) -> None:
        super().__init__(identifier=identifier, min_prior_factors=min_prior_factors)
        self.client_id = client_id
        self.state_service = state_service

    async def start(
        self,
        *,
        provider: str,
        redirect_uri: str,
        scope: list[str] | None = None,
        identity_id: typing.Any | None = None,
        code_challenge_method: CodeChallengeMethod | None = None,
        nonce: str | None = None,
        extra: dict[str, str] | None = None,
    ) -> tuple[str, str, typing.Any]:
        """Start the OAuth2 authorization flow.

        1. Generates PKCE code_verifier/code_challenge if method is provided.
        2. Creates a new OAuth2 state via state_service.create().
        3. Generates the authorization URL via get_authorization_url().
        4. Returns (authorization_url, state_token, oauth2_state).

        Args:
            provider: The OAuth2 provider identifier.
            redirect_uri: The callback URI.
            scope: List of requested scopes.
            identity_id: Optional identity ID to associate with the state.
            code_challenge_method: PKCE method ("S256" or "plain"),
                None to disable PKCE.
            nonce: OpenID Connect nonce for CSRF protection.
            extra: Additional provider-specific parameters.

        Returns:
            A tuple of (authorization_url, state_token, oauth2_state).
            The state_token must be stored by the caller and presented
            during the callback phase.
        """
        # Generate PKCE values if enabled
        code_verifier: str | None = None
        code_challenge: str | None = None
        if code_challenge_method is not None:
            code_verifier = generate_code_verifier()
            code_challenge = generate_code_challenge(
                code_verifier, code_challenge_method
            )

        # Create state
        state_token, oauth2_state = await self.state_service.create(
            provider=provider,
            redirect_uri=redirect_uri,
            identity_id=identity_id,
            nonce=nonce,
            code_verifier=code_verifier,
            scope=scope,
        )

        logger.info(
            "OAuth2 flow started",
            extra={
                "provider": provider,
                "identity_id": identity_id,
                "code_challenge_method": code_challenge_method,
            },
        )

        # Generate authorization URL
        authorization_url = await self.get_authorization_url(
            redirect_uri=redirect_uri,
            scope=scope,
            state=state_token,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            nonce=nonce,
            extra=extra,
        )

        return authorization_url, state_token, oauth2_state

    @abc.abstractmethod
    async def get_authorization_url(
        self,
        *,
        redirect_uri: str,
        scope: list[str] | None = None,
        state: str,
        code_challenge: str | None = None,
        code_challenge_method: CodeChallengeMethod | None = None,
        nonce: str | None = None,
        extra: dict[str, str] | None = None,
    ) -> str:
        """Generate the authorization URL for the OAuth2 provider.

        Provider-specific implementations should construct the URL
        according to their API requirements.

        Args:
            redirect_uri: The callback URI.
            scope: List of requested scopes.
            state: CSRF state token.
            code_challenge: PKCE code challenge.
            code_challenge_method: PKCE method (e.g., "S256").
            nonce: OpenID Connect nonce.
            extra: Additional provider-specific parameters.

        Returns:
            The complete authorization URL.
        """
        ...
