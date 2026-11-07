import hashlib
import hmac
from unittest.mock import AsyncMock, patch

import pytest

from reauth.tokens import (
    HMACTokenVerifier,
    TokenGenerationException,
    TokenVerificationException,
)


def verifier(current: str = "old") -> HMACTokenVerifier:
    return HMACTokenVerifier(
        current_key_id=current, keys={"old": b"o" * 32, "new": b"n" * 32}
    )


@pytest.mark.anyio
async def test_hmac_known_value_and_rotation() -> None:
    old = verifier()
    stored = await old.create("secret")
    expected = hmac.new(b"o" * 32, b"secret", hashlib.sha256).hexdigest()
    assert stored == "hmac-sha256$1$old$" + expected
    rotated = verifier("new")
    with patch.object(rotated, "create", wraps=rotated.create) as create:
        assert await rotated.verify_and_update("wrong", stored) == (False, None)
        create.assert_not_called()
        valid, replacement = await rotated.verify_and_update("secret", stored)
    assert valid and replacement == await rotated.create("secret")
    assert replacement is not None
    assert await rotated.verify_and_update("secret", replacement) == (True, None)


@pytest.mark.parametrize(
    "current,keys",
    [
        ("missing", {"old": b"o" * 32}),
        ("old", {}),
        ("old", {"old": b"short"}),
        ("bad$key", {"bad$key": b"o" * 32}),
        ("old", {"old": b"o" * 32, "bad": b""}),
    ],
)
def test_invalid_key_configuration(current: str, keys: dict[str, bytes]) -> None:
    with pytest.raises(ValueError):
        HMACTokenVerifier(current_key_id=current, keys=keys)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "stored",
    [
        "",
        "legacy-hash",
        "hmac-sha256$2$old$" + "a" * 64,
        "hmac-sha256$1$old$" + "a" * 63,
        "hmac-sha256$1$missing$" + "a" * 64,
        "hmac-sha256$1$old$" + "é" * 64,
    ],
)
async def test_stored_verifier_failures_are_operational(stored: str) -> None:
    with pytest.raises(TokenVerificationException):
        await verifier().verify_and_update("secret", stored)


@pytest.mark.anyio
async def test_encoding_and_upgrade_failure_contracts() -> None:
    current = verifier("new")
    with pytest.raises(TokenGenerationException) as raised:
        await current.create("\ud800")
    assert isinstance(raised.value.__cause__, UnicodeEncodeError)
    stored = await verifier().create("secret")
    assert await current.verify_and_update("\ud800", stored) == (False, None)
    with (
        patch.object(
            current, "create", new=AsyncMock(side_effect=TokenGenerationException)
        ),
        pytest.raises(TokenVerificationException) as raised_upgrade,
    ):
        await current.verify_and_update("secret", stored)
    assert isinstance(raised_upgrade.value.__cause__, TokenGenerationException)
