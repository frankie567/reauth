import asyncio
import string
from unittest.mock import patch

import pytest

from reauth.tokens import (
    ChecksummedTokenProvider,
    HMACTokenVerifier,
    InvalidTokenException,
    TokenGenerationException,
)
from reauth.tokens.checksummed import _checksum


def verifier(current: str = "old") -> HMACTokenVerifier:
    return HMACTokenVerifier(
        current_key_id=current, keys={"old": b"o" * 32, "new": b"n" * 32}
    )


@pytest.mark.anyio
async def test_fixed_format_and_independent_components() -> None:
    provider = ChecksummedTokenProvider(prefix="test_", verifier=verifier())
    with patch(
        "reauth.tokens.checksummed.secrets.choice", side_effect="I" * 16 + "S" * 32
    ):
        generated = await provider.generate()
    parts = provider.parse(generated.token)
    assert parts.identifier == generated.identifier == "I" * 16
    assert parts.secret == "S" * 32
    assert generated.token == "test_" + "I" * 16 + "S" * 32 + _checksum(
        "test_" + "I" * 16 + "S" * 32
    )
    assert await provider.verify_and_update(parts.secret, generated.verifier) == (
        True,
        None,
    )


@pytest.mark.anyio
async def test_random_generation() -> None:
    provider = ChecksummedTokenProvider(prefix="test_", verifier=verifier())
    first = await provider.generate()
    second = await provider.generate()
    assert first.identifier != second.identifier
    assert provider.parse(first.token).secret != provider.parse(second.token).secret
    assert set(first.token[5:]) <= set(string.ascii_letters + string.digits)


@pytest.mark.parametrize("prefix", ["", "préfix_", "space ", "line\n", "dot."])
def test_invalid_prefix_configuration(prefix: str) -> None:
    with pytest.raises(ValueError):
        ChecksummedTokenProvider(prefix=prefix, verifier=verifier())


@pytest.mark.anyio
@pytest.mark.parametrize(
    "change",
    [
        "prefix",
        "short",
        "long",
        "unicode",
        "separator",
        "checksum",
        "identifier",
        "secret",
    ],
)
async def test_reject_malformed_token(change: str) -> None:
    provider = ChecksummedTokenProvider(prefix="test_", verifier=verifier())
    generated = await provider.generate()
    token = generated.token
    malformed = {
        "prefix": "other" + token[5:],
        "short": token[:-1],
        "long": token + "A",
        "unicode": token[:5] + "é" + token[6:],
        "separator": token[:5] + "_" + token[6:],
        "checksum": token[:-6] + "!!!!!!",
        "identifier": token[:5] + ("A" if token[5] != "A" else "B") + token[6:],
        "secret": token[:21] + ("A" if token[21] != "A" else "B") + token[22:],
    }[change]
    with pytest.raises(InvalidTokenException):
        provider.parse(malformed)


@pytest.mark.anyio
async def test_checksum_covers_prefix_and_ascii_validation_precedes_checksum() -> None:
    provider = ChecksummedTokenProvider(prefix="first_", verifier=verifier())
    generated = await provider.generate()
    other = ChecksummedTokenProvider(prefix="other_", verifier=verifier())
    with pytest.raises(InvalidTokenException):
        other.parse("other_" + generated.token[6:])
    value = "first_" + "é" + "a" * 47
    with pytest.raises(InvalidTokenException):
        provider.parse(value + "000000")
    assert _checksum("") == "000000"


@pytest.mark.anyio
async def test_generation_failures_and_cancellation() -> None:
    provider = ChecksummedTokenProvider(prefix="test_", verifier=verifier())
    with (
        patch.object(provider.verifier, "create", side_effect=TokenGenerationException),
        pytest.raises(TokenGenerationException),
    ):
        await provider.generate()
    with (
        patch.object(provider.verifier, "create", side_effect=asyncio.CancelledError),
        pytest.raises(asyncio.CancelledError),
    ):
        await provider.generate()
