import base64
import secrets
import typing

import jwt
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from reauth.factors.oauth2.oidc import (
    InvalidIDTokenException,
    validate_id_token,
)
from reauth.timestamp import get_current_timestamp


def generate_rsa_key() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def get_jwks_from_rsa_key(key: RSAPrivateKey, kid: str) -> jwt.PyJWKSet:
    algorithm = jwt.get_algorithm_by_name("RS256")
    public_jwk = {
        **algorithm.to_jwk(key.public_key(), as_dict=True),
        "kid": kid,
    }
    return jwt.PyJWKSet.from_dict({"keys": [public_jwk]})


def create_id_token(
    key: RSAPrivateKey,
    *,
    issuer: str = "https://issuer.example.com",
    audience: str = "test-client-id",
    subject: str = "test-user-id",
    nonce: str | None = None,
    access_token: str | None = None,
    expires_in: int = 3600,
    issued_at: int | None = None,
    key_id: str = "test-key-1",
) -> str:
    if issued_at is None:
        issued_at = get_current_timestamp()

    claims: dict[str, typing.Any] = {
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "exp": issued_at + expires_in,
        "iat": issued_at,
    }

    if nonce is not None:
        claims["nonce"] = nonce

    if access_token is not None:
        # Compute at_hash using the hash of the access_token
        # For RS256, we use SHA-256
        h = hashes.Hash(hashes.SHA256())
        h.update(access_token.encode())
        digest = h.finalize()
        at_hash = (
            base64.urlsafe_b64encode(digest[: len(digest) // 2]).rstrip(b"=").decode()
        )
        claims["at_hash"] = at_hash

    headers = {"kid": key_id, "alg": "RS256"}

    return jwt.encode(claims, key, algorithm="RS256", headers=headers)


@pytest.fixture
def rsa_key() -> RSAPrivateKey:
    return generate_rsa_key()


@pytest.fixture
def jwks(rsa_key: RSAPrivateKey) -> jwt.PyJWKSet:
    return get_jwks_from_rsa_key(rsa_key, "test-key-1")


class TestValidateIDToken:
    """Tests for the main validate_id_token function."""

    def test_valid_token(self, rsa_key: RSAPrivateKey, jwks: jwt.PyJWKSet) -> None:
        """Test that a valid token passes all validations."""
        token = create_id_token(rsa_key)

        payload = validate_id_token(
            token,
            jwks,
            issuer="https://issuer.example.com",
            client_id="test-client-id",
            id_token_signing_alg_values_supported=["RS256"],
        )

        assert payload["sub"] == "test-user-id"
        assert payload["iss"] == "https://issuer.example.com"
        assert payload["aud"] == "test-client-id"

    def test_valid_token_with_nonce(
        self, rsa_key: RSAPrivateKey, jwks: jwt.PyJWKSet
    ) -> None:
        """Test that a valid token with nonce passes validation."""
        nonce = secrets.token_urlsafe(32)
        token = create_id_token(rsa_key, nonce=nonce)

        payload = validate_id_token(
            token,
            jwks,
            issuer="https://issuer.example.com",
            client_id="test-client-id",
            id_token_signing_alg_values_supported=["RS256"],
            nonce=nonce,
        )

        assert payload["nonce"] == nonce

    def test_valid_token_with_at_hash(
        self, rsa_key: RSAPrivateKey, jwks: jwt.PyJWKSet
    ) -> None:
        """Test that a valid token with at_hash passes validation."""
        access_token = secrets.token_urlsafe(32)
        token = create_id_token(rsa_key, access_token=access_token)

        payload = validate_id_token(
            token,
            jwks,
            issuer="https://issuer.example.com",
            client_id="test-client-id",
            id_token_signing_alg_values_supported=["RS256"],
            access_token=access_token,
        )

        assert payload["sub"] == "test-user-id"
        assert "at_hash" in payload

    def test_invalid_signature(self, rsa_key: RSAPrivateKey) -> None:
        """Test that an invalid signature raises InvalidIDTokenException."""
        token = create_id_token(rsa_key)

        # Create a different JWKS
        other_key = generate_rsa_key()
        other_jwks = get_jwks_from_rsa_key(other_key, "other-key")

        with pytest.raises(InvalidIDTokenException):
            validate_id_token(
                token,
                other_jwks,
                issuer="https://issuer.example.com",
                client_id="test-client-id",
                id_token_signing_alg_values_supported=["RS256"],
            )

    def test_mismatched_nonce(self, rsa_key: RSAPrivateKey, jwks: jwt.PyJWKSet) -> None:
        """Test that a mismatched nonce raises InvalidIDTokenException."""
        token = create_id_token(rsa_key, nonce="token-nonce")

        with pytest.raises(InvalidIDTokenException):
            validate_id_token(
                token,
                jwks,
                issuer="https://issuer.example.com",
                client_id="test-client-id",
                id_token_signing_alg_values_supported=["RS256"],
                nonce="expected-nonce",
            )

    def test_invalid_at_hash(self, rsa_key: RSAPrivateKey, jwks: jwt.PyJWKSet) -> None:
        """Test that an invalid at_hash raises InvalidIDTokenException."""
        access_token = secrets.token_urlsafe(32)
        token = create_id_token(
            rsa_key, key_id="test-key-1", access_token="invalid-access-token"
        )

        with pytest.raises(InvalidIDTokenException):
            validate_id_token(
                token,
                jwks,
                issuer="https://issuer.example.com",
                client_id="test-client-id",
                id_token_signing_alg_values_supported=["RS256"],
                access_token=access_token,
            )

    def test_expired_token(self, rsa_key: RSAPrivateKey, jwks: jwt.PyJWKSet) -> None:
        """Test that an expired token raises InvalidIDTokenException."""
        token = create_id_token(
            rsa_key, expires_in=1, issued_at=get_current_timestamp() - 3600
        )

        with pytest.raises(InvalidIDTokenException):
            validate_id_token(
                token,
                jwks,
                issuer="https://issuer.example.com",
                client_id="test-client-id",
                id_token_signing_alg_values_supported=["RS256"],
            )

    def test_wrong_audience(self, rsa_key: RSAPrivateKey, jwks: jwt.PyJWKSet) -> None:
        """Test that wrong audience raises InvalidIDTokenException."""
        token = create_id_token(rsa_key, audience="test-client-id")

        with pytest.raises(InvalidIDTokenException):
            validate_id_token(
                token,
                jwks,
                issuer="https://issuer.example.com",
                client_id="wrong-client-id",
                id_token_signing_alg_values_supported=["RS256"],
            )

    def test_wrong_issuer(self, rsa_key: RSAPrivateKey, jwks: jwt.PyJWKSet) -> None:
        """Test that wrong issuer raises InvalidIDTokenException."""
        token = create_id_token(rsa_key, issuer="https://issuer.example.com")

        with pytest.raises(InvalidIDTokenException):
            validate_id_token(
                token,
                jwks,
                issuer="https://wrong-issuer.example.com",
                client_id="test-client-id",
                id_token_signing_alg_values_supported=["RS256"],
            )
