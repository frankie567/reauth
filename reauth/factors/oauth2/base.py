import abc
import dataclasses
import typing

from reauth.amr import AuthenticationMethodReference
from reauth.exceptions import ReauthException
from reauth.factors.base import FactorBase
from reauth.factors.oauth2.pkce import (
    CodeChallengeMethod,
    generate_code_challenge,
    generate_code_verifier,
)
from reauth.factors.oauth2.state import OAuth2State, OAuth2StateService
from reauth.logging import get_logger

logger = get_logger(__name__)


@dataclasses.dataclass
class TokenResponse:
    """Result from exchanging authorization code for tokens (RFC 6749 Section 5.1).

    All OAuth2 providers return access_token and related tokens.
    OIDC providers additionally populate id_token.
    """

    account_id: str
    access_token: str
    expires_at: int
    refresh_token: str | None
    refresh_token_expires_at: int | None
    id_token: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.account_id, str):
            self.account_id = str(self.account_id)


@dataclasses.dataclass
class OAuth2Account:
    """
    Authenticated OAuth2 account from callback for new account signup flows.

    Contains all data needed for the application to create an identity and enrollment.
    The application MUST create an identity and call insert() to create the enrollment.
    """

    provider: str
    account_id: str
    access_token: str
    expires_at: int | None
    refresh_token: str | None
    refresh_token_expires_at: int | None
    scope: list[str]
    id_token: str | None = None


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
    id_token: str | None = None

    @classmethod
    def from_account(
        cls, identity_id: typing.Any, account: OAuth2Account
    ) -> typing.Self:
        """Create an OAuth2Enrollment from an OAuth2Account.

        Args:
            identity_id: The identity ID to associate with the enrollment.
            account: The OAuth2Account containing the provider account data.

        Returns:
            A new OAuth2Enrollment instance initialized with the account data.
        """
        return cls(
            id=None,
            identity_id=identity_id,
            provider=account.provider,
            account_id=account.account_id,
            access_token=account.access_token,
            expires_at=account.expires_at,
            refresh_token=account.refresh_token,
            refresh_token_expires_at=account.refresh_token_expires_at,
            scope=account.scope,
            id_token=account.id_token,
        )


class OAuth2Exception(ReauthException):
    """Base exception for OAuth2 errors."""


class OAuth2TokenException(OAuth2Exception):
    """Base exception for OAuth2 token endpoint errors (RFC 6749 Section 5.2)."""

    def __init__(
        self,
        error_description: str | None = None,
        error_uri: str | None = None,
        *,
        state: OAuth2State,
    ) -> None:
        super().__init__(error_description)
        self.error_description = error_description
        self.error_uri = error_uri
        self.state = state


class OAuth2TokenExchangeException(OAuth2TokenException):
    """Raised when token exchange fails."""


class OAuth2TokenInvalidRequestException(OAuth2TokenException):
    """Raised when request is malformed (RFC 6749 token error: invalid_request)."""


class OAuth2TokenUnauthorizedClientException(OAuth2TokenException):
    """Raised when client is not authorized (RFC 6749 token error: unauthorized_client)."""


class OAuth2InvalidClientException(OAuth2TokenException):
    """Raised when client authentication fails (RFC 6749 error: invalid_client)."""


class OAuth2InvalidGrantException(OAuth2TokenException):
    """Raised when authorization grant is invalid/expired (RFC 6749 error: invalid_grant)."""


class OAuth2TokenUnsupportedGrantTypeException(OAuth2TokenException):
    """Raised when grant type is not supported (RFC 6749 token error: unsupported_grant_type)."""


class OAuth2CallbackException(OAuth2Exception):
    """Base exception for OAuth2 callback/authorization errors (RFC 6749 Section 4.1.2.1)."""

    def __init__(self, message: str | None = None, *, state: OAuth2State) -> None:
        super().__init__(message)
        self.state = state


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


class OAuth2GetProfileException(OAuth2Exception):
    """Raised when fetching the identity profile from the provider fails."""


# RFC 6749 authorization endpoint error mapping (Section 4.1.2.1)
_RFC_6749_AUTH_ERROR_MAP: dict[str, type[OAuth2CallbackException]] = {
    "invalid_request": OAuth2InvalidRequestException,
    "unauthorized_client": OAuth2UnauthorizedClientException,
    "access_denied": OAuth2AccessDeniedException,
    "unsupported_response_type": OAuth2UnsupportedResponseTypeException,
    "invalid_scope": OAuth2InvalidScopeException,
    "server_error": OAuth2ServerErrorException,
    "temporarily_unavailable": OAuth2TemporarilyUnavailableException,
}

# RFC 6749 token endpoint error mapping (Section 5.2)
RFC_6749_TOKEN_ERROR_MAP: dict[str, type[OAuth2TokenException]] = {
    "invalid_client": OAuth2InvalidClientException,
    "invalid_grant": OAuth2InvalidGrantException,
    "invalid_request": OAuth2TokenInvalidRequestException,
    "unauthorized_client": OAuth2TokenUnauthorizedClientException,
    "unsupported_grant_type": OAuth2TokenUnsupportedGrantTypeException,
}


class OAuth2Factor[EXTRA](FactorBase[OAuth2Enrollment], abc.ABC):
    AMR: typing.ClassVar[AuthenticationMethodReference] = (
        AuthenticationMethodReference.OAUTH2
    )

    def __init__(
        self,
        *,
        identifier: str,
        client_id: str,
        state_service: OAuth2StateService,
        step: int = 0,
    ) -> None:
        super().__init__(identifier=identifier, step=step)
        self.client_id = client_id
        self.state_service = state_service

    async def start(
        self,
        *,
        redirect_uri: str,
        scope: list[str] | None = None,
        identity_id: typing.Any | None = None,
        code_challenge_method: CodeChallengeMethod | None = None,
        nonce: str | None = None,
        extra: EXTRA | None = None,
        **context: typing.Any,
    ) -> tuple[str, str, OAuth2State]:
        """Start the OAuth2 authorization flow.

        1. Generates PKCE code_verifier/code_challenge if method is provided.
        2. Creates a new OAuth2 state via state_service.create().
        3. Generates the authorization URL via get_authorization_url().
        4. Returns (authorization_url, state_token, oauth2_state).

        Args:
            redirect_uri: The callback URI.
            scope: List of requested scopes.
            identity_id: Optional identity ID to associate with the state.
            code_challenge_method: PKCE method ("S256" or "plain"),
                None to disable PKCE.
            nonce: OpenID Connect nonce for CSRF protection.
            extra: Additional provider-specific parameters.
            **context: Optional keyword arguments for any additional data to store with
                the state.

        Returns:
            A tuple of (authorization_url, state_token, oauth2_state).
            The state_token must be stored by the caller and presented
            during the callback phase.
        """
        logger.debug("OAuth2 start attempted", extra={"provider": self.identifier})
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
            provider=self.identifier,
            redirect_uri=redirect_uri,
            identity_id=identity_id,
            nonce=nonce,
            code_verifier=code_verifier,
            scope=scope,
            **context,
        )

        logger.info(
            "OAuth2 flow started",
            extra={
                "provider": self.identifier,
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
    ) -> (
        tuple[OAuth2Enrollment, None, OAuth2State]
        | tuple[None, OAuth2Account, OAuth2State]
    ):
        """Process OAuth2 callback and complete the authorization flow.

        This is the second step of the OAuth2 authorization code flow (RFC 6749 Section 4.1.2).
        It validates the callback parameters, exchanges the code for tokens,
        resolves the identity, and creates or updates the enrollment.

        Identity resolution priority:
        1. If existing enrollment found for (provider, account_id), use its identity_id
        2. If state has identity_id, use it (associate flow with pre-provisioned identity)
        3. If no existing enrollment and no state.identity_id, return (None, OAuth2Account)
           for signup flow

        For signup flows (case 3), the application MUST create an identity and enrollment
        using the returned OAuth2Account. The factor does NOT create an enrollment
        automatically to avoid dangling enrollments without identities.

        Args:
            code: The authorization code from the callback.
            state: The state token from the callback (must match start() state).
            error: OAuth2 error code if the request was denied (RFC 6749 Section 4.1.2.1).
            error_description: Human-readable error description.
            error_uri: URI for more information about the error.

        Returns:
            A tuple of (enrollment, None, state) for existing users, or (None, account, state)
            for new accounts without a pre-existing identity. The OAuth2State is always
            returned as the third element, containing the original context passed to start().

        Raises:
            InvalidStateException: If the state token is invalid or expired.
            ExpiredStateException: If the state token has expired.
            OAuth2CallbackException: RFC 6749 auth error or unsupported error code.
            OAuth2AccessDeniedException: RFC 6749 auth error: access_denied.
            OAuth2MissingCodeException: If authorization code is missing.
            OAuth2InvalidRequestException: RFC 6749 auth error: invalid_request.
            OAuth2UnauthorizedClientException: RFC 6749 auth error: unauthorized_client.
            OAuth2UnsupportedResponseTypeException: RFC 6749 auth error: unsupported_response_type.
            OAuth2InvalidScopeException: RFC 6749 auth error: invalid_scope.
            OAuth2ServerErrorException: RFC 6749 auth error: server_error.
            OAuth2TemporarilyUnavailableException: RFC 6749 auth error: temporarily_unavailable.
            OAuth2TokenExchangeException: If token exchange fails (see exchange_code).
            OAuth2IdentityMismatchException: If state identity does not match existing enrollment.
        """  # noqa: DOC502
        logger.debug("OAuth2 callback attempted", extra={"provider": self.identifier})
        # Step 1: Consume the state first (validates and deletes atomically)
        oauth2_state = await self.state_service.consume(state)

        # Step 2: Handle OAuth2 error response (RFC 6749 Section 4.1.2.1)
        if error is not None:
            logger.warning(
                "OAuth2 error response received",
                extra={
                    "error": error,
                    "error_description": error_description,
                    "error_uri": error_uri,
                },
            )
            exception_class = _RFC_6749_AUTH_ERROR_MAP.get(error)
            if exception_class is not None:
                raise exception_class(error_description or error, state=oauth2_state)
            raise OAuth2CallbackException(error, state=oauth2_state)

        # Step 3: Validate code is present
        if code is None:
            logger.warning("OAuth2 callback missing code parameter")
            raise OAuth2MissingCodeException(state=oauth2_state)

        logger.debug(
            "OAuth2 callback processing",
            extra={
                "provider": oauth2_state.provider,
                "state_identity_id": oauth2_state.identity_id,
                "state_scope": oauth2_state.scope,
            },
        )

        # Step 4: Exchange code for token
        result = await self.exchange_code(
            code=code,
            redirect_uri=oauth2_state.redirect_uri,
            code_verifier=oauth2_state.code_verifier,
            nonce=oauth2_state.nonce,
            state=oauth2_state,
        )
        scope = oauth2_state.scope or []

        logger.info(
            "OAuth2 token exchange successful",
            extra={
                "provider": oauth2_state.provider,
                "account_id": result.account_id,
            },
        )

        # Step 5: Resolve identity_id
        # Check for existing enrollment by (provider, account_id)
        enrollment = await self.get_enrollment_by_provider_and_account(
            provider=oauth2_state.provider,
            account_id=result.account_id,
        )

        # Existing enrollment flow
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
                        "account_id": result.account_id,
                    },
                )
                raise OAuth2IdentityMismatchException(state=oauth2_state)

            # Step 6: Update existing enrollment
            assert enrollment is not None
            enrollment.access_token = result.access_token
            enrollment.expires_at = result.expires_at
            enrollment.refresh_token = result.refresh_token
            enrollment.refresh_token_expires_at = result.refresh_token_expires_at
            enrollment.scope = scope
            enrollment.id_token = result.id_token
            await self.update(enrollment)
            logger.info(
                "OAuth2 enrollment updated",
                extra={
                    "enrollment_id": enrollment.id,
                    "provider": enrollment.provider,
                    "identity_id": enrollment.identity_id,
                },
            )

            return (enrollment, None, oauth2_state)

        # Associate flow with pre-provisioned identity_id
        if oauth2_state.identity_id is not None:
            identity_id = oauth2_state.identity_id

            # Step 6: Use scope from state (not from token response)
            final_scope = oauth2_state.scope or []

            # Step 7: Create new enrollment
            enrollment = OAuth2Enrollment(
                id=None,
                identity_id=identity_id,
                provider=oauth2_state.provider,
                account_id=result.account_id,
                access_token=result.access_token,
                expires_at=result.expires_at,
                refresh_token=result.refresh_token,
                refresh_token_expires_at=result.refresh_token_expires_at,
                scope=final_scope,
                id_token=result.id_token,
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

            return (enrollment, None, oauth2_state)

        # Signup flow - no existing enrollment, no identity_id in state
        # Return account WITHOUT creating enrollment
        logger.info(
            "OAuth2 callback: new account, awaiting identity creation",
            extra={
                "provider": oauth2_state.provider,
                "account_id": result.account_id,
            },
        )
        return (
            None,
            OAuth2Account(
                provider=oauth2_state.provider,
                account_id=result.account_id,
                access_token=result.access_token,
                expires_at=result.expires_at,
                refresh_token=result.refresh_token,
                refresh_token_expires_at=result.refresh_token_expires_at,
                scope=oauth2_state.scope or [],
                id_token=result.id_token,
            ),
            oauth2_state,
        )

    async def enroll(
        self, identity_id: typing.Any, oauth2_account: OAuth2Account
    ) -> OAuth2Enrollment:
        """
        Enroll a new OAuth2 factor for a given identity using an OAuth2Account.

        This is used for signup flows where the callback wasn't able to directly return
        an enrollment because there was no pre-existing identity.

        Args:
            identity_id: The ID of the identity to enroll the factor for.
            oauth2_account: The OAuth2Account data returned from callback().

        Returns:
            The newly created OAuth2Enrollment instance.
        """
        logger.debug("OAuth2 enroll attempted", extra={"identity_id": identity_id})
        enrollment = OAuth2Enrollment.from_account(identity_id, oauth2_account)
        enrollment.id = await self.insert(enrollment)
        logger.info(
            "OAuth2 enrollment created",
            extra={
                "enrollment_id": enrollment.id,
                "provider": enrollment.provider,
                "identity_id": enrollment.identity_id,
            },
        )
        return enrollment

    @abc.abstractmethod
    async def get_client_secret(self) -> str:
        """Get the client secret for token exchange.

        This method retrieves the client secret used for client authentication
        during the OAuth 2.0 token exchange (RFC 6749 Section 4.1.3).
        Implementations may return a static secret, fetch it from a secure vault,
        or generate it dynamically (e.g., for providers like Apple that require
        JWT-based client secrets).

        Returns:
            The client secret string.
        """
        ...

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
        extra: EXTRA | None = None,
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
        nonce: str | None = None,
        state: OAuth2State,
    ) -> TokenResponse:
        """Exchange authorization code for access token (RFC 6749 Section 4.1.3).

        Provider-specific implementations should call their token endpoint
        and return the token response data. Use self.client_id and get_client_secret()
        for client authentication as required by the provider.

        Args:
            code: The authorization code from the callback.
            redirect_uri: The redirect URI used in the authorization request.
            code_verifier: PKCE code verifier (if PKCE was used).
            nonce: OpenID Connect nonce for ID Token validation.
            state: The OAuth2 state for this flow, to be passed to exceptions.

        Returns:
            TokenResponse with account_id, access_token, expires_at, refresh_token,
            refresh_token_expires_at, and optionally id_token for OIDC providers.

        Raises:
            OAuth2TokenExchangeException: If token exchange fails.
            OAuth2InvalidClientException: RFC 6749 token error: invalid_client.
            OAuth2InvalidGrantException: RFC 6749 token error: invalid_grant.
            OAuth2TokenInvalidRequestException: RFC 6749 token error: invalid_request.
            OAuth2TokenUnauthorizedClientException: RFC 6749 token error: unauthorized_client.
            OAuth2TokenUnsupportedGrantTypeException: RFC 6749 token error: unsupported_grant_type.
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

    @abc.abstractmethod
    async def get_profile(self, access_token: str) -> dict[str, typing.Any]:
        """Fetch user profile from the provider.

        OAuth2 providers must implement this to fetch profile data using the
        access_token at the provider's userinfo endpoint or equivalent.

        For providers that don't support fetching profile data (e.g., Apple),
        implementations should raise NotImplementedError.

        Common claim keys (not exhaustive):
        - sub (str): Unique user identifier at the provider
        - email (str | None): User's email address
        - email_verified (bool | None): Whether email is verified
        - name (str | None): User's display name
        - given_name (str | None): First name
        - family_name (str | None): Last name
        - picture (str | None): Profile picture URL
        - locale (str | None): User's locale

        Args:
            access_token: The OAuth2 access token for making authenticated requests.

        Returns:
            Provider-specific profile claims.

        Raises:
            NotImplementedError: If the provider doesn't support profile fetching.
            OAuth2GetProfileException: If fetching the profile fails.
        """
        ...
