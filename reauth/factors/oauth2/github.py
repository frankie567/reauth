import abc
import typing
import urllib.parse

import httpx

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


class GitHubOAuth2Extra(typing.TypedDict, total=False):
    """Extra parameters for GitHub OAuth2 authorization URL.

    References:
        - GitHub: https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
    """

    login: str
    allow_signup: typing.Literal["true", "false"]
    prompt: typing.Literal["select_account"]


class GitHubEmail(typing.TypedDict):
    """GitHub email address object from the emails endpoint."""

    email: str
    primary: bool
    verified: bool
    visibility: typing.Literal["public", "private"]


def get_primary_email(emails: list[GitHubEmail]) -> str:
    """Get the primary email address from a list of GitHubEmail objects.

    Args:
        emails: A list of GitHubEmail objects representing the email addresses associated with the account.

    Returns:
        The primary email address.

    Raises:
        ValueError: If no primary email is found in the list.
    """
    for email in emails:
        if email["primary"]:
            return email["email"]
    raise ValueError()


class GitHubOAuth2GetEmailsException(OAuth2Exception):
    """Raised when fetching the email addresses from GitHub fails."""


class GitHubOAuth2Factor(OAuth2Factor[GitHubOAuth2Extra], abc.ABC):
    """
    GitHub OAuth2 factor implementation, using the standard OAuth2 protocol.

    Depending on the user settings, emails may not be included in the profile response.
    To get all the emails associated with the account, use the `get_emails` method with the access token.
    The scope `user:email` is required to access the emails endpoint.

    References:
        - GitHub: https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
    """

    AUTHORIZATION_ENDPOINT = "https://github.com/login/oauth/authorize"
    TOKEN_ENDPOINT = "https://github.com/login/oauth/access_token"
    PROFILE_ENDPOINT = "https://api.github.com/user"
    EMAILS_ENDPOINT = "https://api.github.com/user/emails"

    def __init__(
        self,
        *,
        identifier: str = "github",
        client_id: str,
        client_secret: str,
        state_service: OAuth2StateService,
        step: int = 0,
    ) -> None:
        super().__init__(
            identifier=identifier,
            step=step,
            client_id=client_id,
            state_service=state_service,
        )
        self._client_secret = client_secret
        self._client = httpx.AsyncClient()

    async def get_client_secret(self) -> str:
        return self._client_secret

    async def get_authorization_url(
        self,
        *,
        redirect_uri: str,
        scope: list[str] | None = None,
        state: str,
        code_challenge: str | None = None,
        code_challenge_method: CodeChallengeMethod | None = None,
        nonce: str | None = None,
        extra: GitHubOAuth2Extra | None = None,
    ) -> str:
        logger.debug(
            "GitHub get_authorization_url called", extra={"provider": self.identifier}
        )
        scope = scope or []

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

        if extra is not None:
            params = {**params, **extra}

        return f"{self.AUTHORIZATION_ENDPOINT}?{urllib.parse.urlencode(params)}"

    async def exchange_code(
        self,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str | None = None,
        nonce: str | None = None,
        state: OAuth2State,
    ) -> TokenResponse:
        logger.debug("GitHub exchange_code called", extra={"provider": self.identifier})
        client_secret = await self.get_client_secret()
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": self.client_id,
            "client_secret": client_secret,
        }
        if code_verifier is not None:
            data["code_verifier"] = code_verifier

        client = self._get_client()
        try:
            response = await client.post(
                self.TOKEN_ENDPOINT,
                headers={"Accept": "application/json"},
                data=data,
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

            try:
                profile = await self.get_profile(access_token)
            except OAuth2GetProfileException as e:
                raise OAuth2TokenExchangeException(state=state) from e
            account_id = profile["id"]

            return TokenResponse(
                account_id=account_id,
                access_token=access_token,
                expires_at=expires_at,
                refresh_token=refresh_token,
                refresh_token_expires_at=refresh_token_expires_at,
            )

        raise OAuth2TokenExchangeException(state=state)

    async def get_profile(self, access_token: str) -> dict[str, typing.Any]:
        client = self._get_client()
        try:
            response = await client.get(
                self.PROFILE_ENDPOINT,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            response.raise_for_status()
        except httpx.HTTPError as e:
            raise OAuth2GetProfileException() from e

        return response.json()

    async def get_emails(self, access_token: str) -> list[GitHubEmail]:
        """Fetch the list of email addresses associated with the GitHub account.

        This requires the `user:email` scope to be granted by the user during authorization.

        Args:
            access_token: The OAuth2 access token for making authenticated requests.

        Returns:
            A list of GitHubEmail objects representing the email addresses associated with the account.

        Raises:
            GitHubOAuth2GetEmailsException: If the request to fetch emails fails.
        """
        client = self._get_client()
        try:
            response = await client.get(
                self.EMAILS_ENDPOINT,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            response.raise_for_status()
        except httpx.HTTPError as e:
            raise GitHubOAuth2GetEmailsException() from e

        return response.json()

    def _get_client(self) -> httpx.AsyncClient:  # pragma: no cover
        return self._client
