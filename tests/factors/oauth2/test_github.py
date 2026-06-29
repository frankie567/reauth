import pytest

from reauth.factors.oauth2.base import OAuth2Enrollment
from reauth.factors.oauth2.github import GitHubOAuth2Factor

from .conftest import SQLAlchemyOAuth2StateService


class _GitHubFactor(GitHubOAuth2Factor):
    async def insert(self, enrollment: OAuth2Enrollment) -> int:
        raise NotImplementedError()

    async def update(self, enrollment: OAuth2Enrollment) -> None:
        raise NotImplementedError()

    async def get_enrollment_by_provider_and_account(
        self, provider: str, account_id: str
    ) -> OAuth2Enrollment | None:
        raise NotImplementedError()

    async def get_enrollment(self, identity_id: int) -> OAuth2Enrollment | None:
        raise NotImplementedError()


@pytest.mark.anyio
class TestGitHubFactorGetRequestAuthentication:
    """Tests for GitHubOAuth2Factor.get_request_authentication()."""

    async def test_returns_credentials_in_body(
        self, oauth2_state_service: SQLAlchemyOAuth2StateService
    ) -> None:
        """GitHub authenticates with client_id/client_secret in the request body."""
        factor = _GitHubFactor(
            client_id="github-client-id",
            client_secret="github-client-secret",
            state_service=oauth2_state_service,
        )

        headers, body = await factor.get_request_authentication(
            token_endpoint=GitHubOAuth2Factor.TOKEN_ENDPOINT
        )

        assert headers == {}
        assert body == {
            "client_id": "github-client-id",
            "client_secret": "github-client-secret",
        }
