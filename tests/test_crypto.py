"""Tests for reauth.crypto module."""

import pytest

from reauth.crypto import (
    generate_code_hash_pair,
    generate_token,
    generate_token_hash_pair,
    get_token_hash,
)


class TestGetTokenHash:
    """Tests for get_token_hash function."""

    @pytest.mark.parametrize(
        "token,secret",
        [
            ("test_token", "test_secret"),
            ("another_token", "another_secret"),
            ("a" * 100, "b" * 100),
            ("token_with_special!@#", "secret$%^&*()"),
            ("", "secret"),
            ("token", ""),
        ],
    )
    def test_returns_hex_string(self, token: str, secret: str) -> None:
        result = get_token_hash(token, secret=secret)
        assert isinstance(result, str)
        assert all(c in "0123456789abcdef" for c in result)

    def test_hex_length_is_64(self) -> None:
        """SHA256 produces 64 hex characters."""
        result = get_token_hash("any_token", secret="any_secret")
        assert len(result) == 64

    def test_deterministic(self) -> None:
        """Same inputs produce same output."""
        token = "my_token"
        secret = "my_secret"
        result1 = get_token_hash(token, secret=secret)
        result2 = get_token_hash(token, secret=secret)
        assert result1 == result2

    def test_different_secrets_produce_different_hashes(self) -> None:
        """Different secrets produce different hashes for same token."""
        token = "same_token"
        hash1 = get_token_hash(token, secret="secret1")
        hash2 = get_token_hash(token, secret="secret2")
        assert hash1 != hash2


class TestGenerateToken:
    """Tests for generate_token function."""

    def test_default_length(self) -> None:
        """Default token has 37 random chars + 6 checksum chars = 43."""
        token = generate_token()
        assert len(token) == 43

    @pytest.mark.parametrize("prefix", ["", "user_", "api:", "a" * 10])
    def test_length_with_prefix(self, prefix: str) -> None:
        """Token length is prefix + 37 random + 6 checksum."""
        token = generate_token(prefix=prefix)
        assert len(token) == len(prefix) + 43

    def test_starts_with_prefix(self) -> None:
        """Token starts with the provided prefix."""
        prefix = "custom_"
        token = generate_token(prefix=prefix)
        assert token.startswith(prefix)

    def test_token_format(self) -> None:
        """Token has 37 alphanumeric chars followed by 6 checksum chars."""
        token = generate_token()
        assert len(token) == 43
        assert token[:37].isalnum()
        # Checksum uses base62: 0-9, A-Z, a-z
        valid_chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        assert all(c in valid_chars for c in token[37:])

    def test_token_format_with_prefix(self) -> None:
        """Token with prefix has prefix + 37 alphanumeric + 6 checksum."""
        prefix = "prefix_"
        token = generate_token(prefix=prefix)
        assert len(token) == len(prefix) + 43
        assert token.startswith(prefix)
        assert token[len(prefix) : len(prefix) + 37].isalnum()
        valid_chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        assert all(c in valid_chars for c in token[len(prefix) + 37 :])

    def test_random_part_is_alphanumeric(self) -> None:
        """The random part contains only alphanumeric characters."""
        token = generate_token()
        random_part = token[:37]
        assert random_part.isalnum()

    @pytest.mark.parametrize("n", range(10))
    def test_tokens_are_unique(self, n: int) -> None:
        """Generated tokens are unique (very low collision probability)."""
        tokens = [generate_token() for _ in range(100)]
        assert len(set(tokens)) == 100


class TestGenerateTokenHashPair:
    """Tests for generate_token_hash_pair function."""

    def test_returns_tuple_of_two_strings(self) -> None:
        """Returns a tuple of (token, hash)."""
        token, hash_value = generate_token_hash_pair(secret="my_secret")
        assert isinstance(token, str)
        assert isinstance(hash_value, str)

    def test_hash_matches_get_token_hash(self) -> None:
        """Hash in pair matches get_token_hash output."""
        secret = "test_secret"
        token, hash_value = generate_token_hash_pair(secret=secret)
        expected_hash = get_token_hash(token, secret=secret)
        assert hash_value == expected_hash

    @pytest.mark.parametrize("prefix", ["", "user_", "api:"])
    def test_token_has_prefix(self, prefix: str) -> None:
        """Token in pair has the specified prefix."""
        token, _ = generate_token_hash_pair(secret="secret", prefix=prefix)
        assert token.startswith(prefix)

    @pytest.mark.parametrize("prefix", ["", "user_", "api:"])
    def test_token_length_with_prefix(self, prefix: str) -> None:
        """Token in pair has correct length with prefix."""
        token, _ = generate_token_hash_pair(secret="secret", prefix=prefix)
        assert len(token) == len(prefix) + 43

    def test_hash_is_valid_hex(self) -> None:
        """Hash in pair is a valid hexadecimal string."""
        _, hash_value = generate_token_hash_pair(secret="secret")
        assert all(c in "0123456789abcdef" for c in hash_value)
        assert len(hash_value) == 64


class TestGenerateCodeHashPair:
    """Tests for generate_code_hash_pair function."""

    @pytest.mark.parametrize("length", [1, 4, 6, 8, 10])
    def test_code_properties(self, length: int) -> None:
        """Code has correct length and valid characters, hash is valid hex."""
        code, hash_value = generate_code_hash_pair(secret="my_secret", length=length)

        # Length check
        assert len(code) == length

        # Character set check (uppercase alphanumeric only)
        valid_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        assert all(c in valid_chars for c in code)

        # Hash is present and valid
        assert isinstance(hash_value, str)
        assert all(c in "0123456789abcdef" for c in hash_value)
        assert len(hash_value) == 64
