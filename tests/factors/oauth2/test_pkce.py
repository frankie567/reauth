import re

import pytest

from reauth.factors.oauth2.pkce import (
    CodeChallengeMethod,
    generate_code_challenge,
    generate_code_verifier,
)

# RFC 7636 Section 4.1: code_verifier must use unreserved URI characters
UNRESERVED_URI_PATTERN = re.compile(r"^[A-Za-z0-9\-._~]+$")


class TestGenerateCodeVerifier:
    def test_generates_valid_code_verifier(self) -> None:
        code_verifier = generate_code_verifier()

        # Type
        assert isinstance(code_verifier, str)
        assert len(code_verifier) >= 43  # RFC 7636 minimum

        # RFC 7636 ABNF: only unreserved URI characters
        assert UNRESERVED_URI_PATTERN.match(code_verifier)

        # URL-safe (no base64 padding or special chars)
        assert "=" not in code_verifier
        assert "/" not in code_verifier
        assert "+" not in code_verifier


class TestGenerateCodeChallenge:
    @pytest.mark.parametrize("method", ["S256", "plain"])
    def test_produces_url_safe_string(self, method: CodeChallengeMethod) -> None:
        code_verifier = generate_code_verifier()
        code_challenge = generate_code_challenge(code_verifier, method)

        assert "/" not in code_challenge
        assert "+" not in code_challenge
        assert "=" not in code_challenge
