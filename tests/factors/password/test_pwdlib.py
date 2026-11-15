import pwdlib.exceptions
import pytest

from reauth.factors.password.hashing import (
    PasswordHashGenerationException,
    PasswordHashVerificationException,
)
from reauth.factors.password.pwdlib import PwdlibPasswordHash


def test_round_trip():
    hasher = PwdlibPasswordHash()
    stored = hasher.hash("secret")
    assert hasher.verify("secret", stored)
    assert not hasher.verify("wrong", stored)
    assert hasher.verify_and_update("secret", stored) == (True, None)
    assert hasher.verify_and_update("wrong", stored) == (False, None)


@pytest.mark.parametrize("method", ["verify", "verify_and_update"])
def test_invalid_hash(method):
    with pytest.raises(PasswordHashVerificationException) as exc:
        getattr(PwdlibPasswordHash(), method)("secret", "unknown")
    assert exc.value.__cause__ is not None


@pytest.mark.parametrize(
    ("method", "exception"),
    [
        ("hash", PasswordHashGenerationException),
        ("verify_and_update", PasswordHashVerificationException),
    ],
)
def test_hashing_failure(monkeypatch, method, exception):
    hasher = PwdlibPasswordHash()
    error = pwdlib.exceptions.HashGenerationError()

    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(hasher._impl, method, fail)
    args = ("secret",) if method == "hash" else ("secret", "stored")
    with pytest.raises(exception) as exc:
        getattr(hasher, method)(*args)
    assert exc.value.__cause__ is error


def test_programming_error():
    with pytest.raises(TypeError):
        PwdlibPasswordHash().hash(None)  # ty: ignore[invalid-argument-type]


@pytest.mark.parametrize("method", ["verify", "verify_and_update"])
def test_verification_failure(monkeypatch, method):
    hasher = PwdlibPasswordHash()
    error = pwdlib.exceptions.HashVerificationError()

    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(hasher._impl, method, fail)
    with pytest.raises(PasswordHashVerificationException) as exc:
        getattr(hasher, method)("secret", "stored")
    assert exc.value.__cause__ is error
