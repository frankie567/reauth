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


class OAuth2CallbackException(OAuth2Exception):
    """Base exception for OAuth2 callback errors."""


class OAuth2TokenExchangeException(OAuth2Exception):
    """Raised when token exchange fails."""


class OAuth2AccessDeniedException(OAuth2CallbackException):
    """Raised when the user denies authorization (RFC 6749 error: access_denied)."""


class OAuth2InvalidRequestException(OAuth2CallbackException):
    """Raised when a required parameter is missing (RFC 6749 error: invalid_request)."""


class OAuth2UnauthorizedClientException(OAuth2CallbackException):
    """Raised when the client is not authorized (RFC 6749 error: unauthorized_client)."""


class OAuth2UnsupportedResponseTypeException(OAuth2CallbackException):
    """Raised for unsupported response type (RFC 6749 error: unsupported_response_type)."""


class OAuth2InvalidScopeException(OAuth2CallbackException):
    """Raised when the requested scope is invalid (RFC 6749 error: invalid_scope)."""


class OAuth2ServerErrorException(OAuth2CallbackException):
    """Raised for server errors (RFC 6749 error: server_error)."""


class OAuth2TemporarilyUnavailableException(OAuth2CallbackException):
    """Raised when the server is temporarily unavailable (RFC 6749 error: temporarily_unavailable)."""


class OAuth2MissingCodeException(OAuth2CallbackException):
    """Raised when authorization code is missing from callback."""


class OAuth2IdentityMismatchException(OAuth2CallbackException):
    """Raised when state identity does not match existing enrollment."""


class OAuth2NoIdentityException(OAuth2CallbackException):
    """Raised when no existing enrollment and no identity_id in state."""


# RFC 6749 error mapping
_RFC_6749_ERROR_MAP: dict[str, type[OAuth2CallbackException]] = {
    "invalid_request": OAuth2InvalidRequestException,
    "unauthorized_client": OAuth2UnauthorizedClientException,
    "access_denied": OAuth2AccessDeniedException,
    "unsupported_response_type": OAuth2UnsupportedResponseTypeException,
    "invalid_scope": OAuth2InvalidScopeException,
    "server_error": OAuth2ServerErrorException,
    "temporarily_unavailable": OAuth2TemporarilyUnavailableException,
}


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

    async def callback(
        self,
        *,
        code: str | None = None,
        state: str,
        error: str | None = None,
        error_description: str | None = None,
        error_uri: str | None = None,
    ) -> OAuth2Enrollment:
        """Process OAuth2 callback and complete the authorization flow.

        This is the second step of the OAuth2 authorization code flow.
        It validates the callback parameters, exchanges the code for tokens,
        resolves the identity, and creates or updates the enrollment.

        Identity resolution priority:
        1. If existing enrollment found for (provider, account_id), use its identity_id
        2. If state has identity_id, it must match existing enrollment's identity_id
        3. If no existing enrollment, state.identity_id is required

        Args:
            code: The authorization code from the callback.
            state: The state token from the callback (must match start() state).
            error: OAuth2 error code if the request was denied.
            error_description: Human-readable error description.
            error_uri: URI for more information about the error.

        Returns:
            The OAuth2Enrollment instance (created or updated).

        Raises:
            InvalidStateException: If the state token is invalid or expired.
            OAuth2AccessDeniedException: If user denied authorization.
            OAuth2MissingCodeException: If authorization code is missing.
            OAuth2CallbackException: If callback processing fails.
            OAuth2TokenExchangeException: If token exchange fails.
            OAuth2InvalidRequestException: RFC error: invalid_request.
            OAuth2UnauthorizedClientException: RFC error: unauthorized_client.
            OAuth2UnsupportedResponseTypeException: RFC error: unsupported_response_type.
            OAuth2InvalidScopeException: RFC error: invalid_scope.
            OAuth2ServerErrorException: RFC error: server_error.
            OAuth2TemporarilyUnavailableException: RFC error: temporarily_unavailable.
        """
        # Step 1: Handle OAuth2 error response (RFC 6749 Section 4.1.2.1)
        if error is not None:
            logger.warning(
                "OAuth2 error response received",
                extra={
                    "error": error,
                    "error_description": error_description,
                    "error_uri": error_uri,
                },
            )
            exception_class = _RFC_6749_ERROR_MAP.get(error)
            if exception_class is not None:
                raise exception_class(error_description or error)
            raise OAuth2CallbackException(error)

        # Step 2: Validate code is present
        if code is None:
            logger.warning("OAuth2 callback missing code parameter")
            raise OAuth2MissingCodeException()

        # Step 3: Consume the state (validates and deletes atomically)
        oauth2_state = await self.state_service.consume(state)

        logger.debug(
            "OAuth2 callback processing",
            extra={
                "provider": oauth2_state.provider,
                "state_identity_id": oauth2_state.identity_id,
                "state_scope": oauth2_state.scope,
            },
        )

        # Step 4: Exchange code for token
        (
            access_token,
            account_id,
            expires_at,
            refresh_token,
            refresh_token_expires_at,
        ) = await self.exchange_code(
            code=code,
            redirect_uri=oauth2_state.redirect_uri,
            code_verifier=oauth2_state.code_verifier,
        )

        logger.info(
            "OAuth2 token exchange successful",
            extra={
                "provider": oauth2_state.provider,
                "account_id": account_id,
            },
        )

        # Step 5: Resolve identity_id
        # Check for existing enrollment by (provider, account_id)
        enrollment = await self.get_enrollment_by_provider_and_account(
            provider=oauth2_state.provider,
            account_id=account_id,
        )

        if enrollment is not None:
            # Use identity from existing enrollment
            identity_id = enrollment.identity_id

            # If state also has identity_id, verify they match
            if (
                oauth2_state.identity_id is not None
                and oauth2_state.identity_id != identity_id
            ):
                logger.warning(
                    "OAuth2 callback identity mismatch",
                    extra={
                        "state_identity_id": oauth2_state.identity_id,
                        "enrollment_identity_id": identity_id,
                        "provider": oauth2_state.provider,
                        "account_id": account_id,
                    },
                )
                raise OAuth2IdentityMismatchException()
            is_new_enrollment = False
        else:
            # No existing enrollment - must have identity_id from state
            if oauth2_state.identity_id is None:
                logger.warning(
                    "OAuth2 callback with new account but no identity_id in state",
                    extra={
                        "provider": oauth2_state.provider,
                        "account_id": account_id,
                    },
                )
                raise OAuth2NoIdentityException()
            identity_id = oauth2_state.identity_id
            is_new_enrollment = True

        # Step 6: Use scope from state (not from token response)
        final_scope = oauth2_state.scope or []

        # Step 7: Create or update enrollment
        if is_new_enrollment:
            enrollment = OAuth2Enrollment(
                id=None,
                identity_id=identity_id,
                provider=oauth2_state.provider,
                account_id=account_id,
                access_token=access_token,
                expires_at=expires_at,
                refresh_token=refresh_token,
                refresh_token_expires_at=refresh_token_expires_at,
                scope=final_scope,
            )
            enrollment.id = await self.insert(enrollment)
            logger.info(
                "OAuth2 enrollment created",
                extra={
                    "enrollment_id": enrollment.id,
                    "provider": enrollment.provider,
                    "identity_id": enrollment.identity_id,
                },
            )
        else:
            assert enrollment is not None
            enrollment.access_token = access_token
            enrollment.expires_at = expires_at
            enrollment.refresh_token = refresh_token
            enrollment.refresh_token_expires_at = refresh_token_expires_at
            enrollment.scope = final_scope
            await self.update(enrollment)
            logger.info(
                "OAuth2 enrollment updated",
                extra={
                    "enrollment_id": enrollment.id,
                    "provider": enrollment.provider,
                    "identity_id": enrollment.identity_id,
                },
            )

        return enrollment

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

    @abc.abstractmethod
    async def exchange_code(
        self,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str | None = None,
    ) -> tuple[str, str, int, str | None, int | None]:
        """Exchange authorization code for access token.

        Provider-specific implementations should call their token endpoint
        and return the token response data.

        Args:
            code: The authorization code from the callback.
            redirect_uri: The redirect URI used in the authorization request.
            code_verifier: PKCE code verifier (if PKCE was used).

        Returns:
            A tuple of:
            (access_token, account_id, expires_at, refresh_token, refresh_token_expires_at)

            Note: scope is NOT returned here - use oauth2_state.scope instead.

        Raises:
            OAuth2TokenExchangeException: If token exchange fails.
            OAuth2CallbackException: For RFC-defined errors from token endpoint.
        """
        ...

    @abc.abstractmethod
    async def insert(self, enrollment: OAuth2Enrollment) -> typing.Any:
        """Insert an OAuth2 enrollment into a persistent store.

        Args:
            enrollment: The OAuth2Enrollment instance to insert.

        Returns:
            The ID of the inserted OAuth2Enrollment.
        """
        ...

    @abc.abstractmethod
    async def update(self, enrollment: OAuth2Enrollment) -> None:
        """Update an OAuth2 enrollment in a persistent store.

        Args:
            enrollment: The OAuth2Enrollment instance to update.
        """
        ...

    @abc.abstractmethod
    async def get_enrollment_by_provider_and_account(
        self,
        provider: str,
        account_id: str,
    ) -> OAuth2Enrollment | None:
        """Get enrollment by provider and account ID.

        Args:
            provider: The OAuth2 provider.
            account_id: The provider-specific account/user ID.

        Returns:
            The OAuth2Enrollment instance, or None if not found.
        """
        ...
