import datetime
import hashlib

import cbor2
import pytest
import sqlalchemy as sa
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

from reauth.factors.webauthn import (
    AttestationFormat,
    AttestationRejectedException,
    InvalidAuthenticationException,
    InvalidRegistrationException,
    WebAuthnEnrollment,
)
from reauth.factors.webauthn.state import InvalidStateException
from tests.webauthn import (
    CREDENTIAL_ID,
    PUBLIC_KEY,
    RP,
    response,
    seed_enrollment,
    seed_state,
)


@pytest.mark.anyio
async def test_start_options_and_storage(webauthn_factor, webauthn_tables):
    for credential_id in (CREDENTIAL_ID, b"spare"):
        await seed_enrollment(webauthn_factor, webauthn_tables, credential_id)
    token, creation = await webauthn_factor.start_enrollment(
        identity_id=42, session_id=5, user_name="account"
    )
    assert creation.user.id == (42).to_bytes(16)
    assert creation.authenticator_selection.require_resident_key
    assert [c.id for c in creation.exclude_credentials] == [CREDENTIAL_ID, b"spare"]
    _, known = await webauthn_factor.start_authentication(identity_id=42, session_id=5)
    _, discoverable = await webauthn_factor.start_authentication(session_id=5)
    assert [c.id for c in known.allow_credentials] == [CREDENTIAL_ID, b"spare"]
    assert discoverable.allow_credentials is None
    with pytest.raises(InvalidAuthenticationException):
        await webauthn_factor.start_authentication(identity_id=7, session_id=5)
    rows = (
        (
            await webauthn_factor.connection.execute(
                sa.select(webauthn_tables[1]).order_by(webauthn_tables[1].c.id)
            )
        )
        .mappings()
        .all()
    )
    assert [r["challenge"] for r in rows] == [
        creation.challenge,
        known.challenge,
        discoverable.challenge,
    ]
    assert len({r["challenge"] for r in rows}) == 3
    assert (
        rows[0]["token_identifier"]
        == webauthn_factor.state_service.token_provider.parse(token).identifier
    )


@pytest.mark.parametrize("reject", [False, True])
@pytest.mark.anyio
async def test_finish_enrollment(webauthn_factor, webauthn_tables, reject):
    token = await seed_state(webauthn_factor, webauthn_tables, "enrollment", 42)
    if reject:

        async def reject_none(registration):
            return registration.fmt != "none"

        webauthn_factor.accept_attestation = reject_none
        with pytest.raises(AttestationRejectedException):
            await webauthn_factor.finish_enrollment(
                state_token=token, session_id=5, credential=response(registration=True)
            )
        assert (
            await webauthn_factor.connection.scalar(sa.select(webauthn_tables[0].c.id))
            is None
        )
    else:
        enrolled = await webauthn_factor.finish_enrollment(
            state_token=token, session_id=5, credential=response(registration=True)
        )
        assert enrolled == WebAuthnEnrollment(
            enrolled.id,
            42,
            RP,
            webauthn_factor.identifier,
            CREDENTIAL_ID,
            PUBLIC_KEY,
            8,
        )
        assert await webauthn_factor.get_enrollments(42) == [enrolled]
    assert (
        await webauthn_factor.connection.scalar(sa.select(webauthn_tables[1].c.id))
        is None
    )


@pytest.mark.anyio
@pytest.mark.parametrize("existing_rp", [RP, "other.example"])
async def test_registration_with_credential_id_from_another_factor(
    webauthn_factor, webauthn_tables, existing_rp
):
    enrollments, _ = webauthn_tables
    await webauthn_factor.connection.execute(
        enrollments.insert().values(
            identity_id=17,
            rp_id=existing_rp,
            factor_identifier="other-factor",
            credential_id=CREDENTIAL_ID,
            public_key=PUBLIC_KEY,
            sign_count=7,
        )
    )
    token = await seed_state(webauthn_factor, webauthn_tables, "enrollment", 42)
    registration = webauthn_factor.finish_enrollment(
        state_token=token, session_id=5, credential=response(registration=True)
    )
    if existing_rp == RP:
        with pytest.raises(InvalidRegistrationException):
            await registration
    else:
        enrollment = await registration
        assert enrollment.rp_id == RP
        assert enrollment.identity_id == 42


@pytest.mark.anyio
async def test_invalid_registration(webauthn_factor, webauthn_tables):
    token = await seed_state(webauthn_factor, webauthn_tables, "enrollment", 42)
    with pytest.raises(InvalidRegistrationException):
        await webauthn_factor.finish_enrollment(
            state_token=token,
            session_id=5,
            credential=response(registration=True, flags=1),
        )
    assert await webauthn_factor.get_enrollments(42) == []


@pytest.mark.parametrize(
    ("identity_id", "handle"), [(42, None), (None, (42).to_bytes(16))]
)
@pytest.mark.anyio
async def test_finish_authentication(
    webauthn_factor, webauthn_tables, identity_id, handle
):
    await seed_enrollment(webauthn_factor, webauthn_tables)
    token = await seed_state(webauthn_factor, webauthn_tables, identity_id=identity_id)
    credential = response(handle=handle)
    result = await webauthn_factor.finish_authentication(
        state_token=token, session_id=5, credential=credential
    )
    assert result.identity_id == 42
    assert (
        await webauthn_factor.connection.scalar(
            sa.select(webauthn_tables[0].c.sign_count)
        )
        == 8
    )
    with pytest.raises(InvalidStateException):
        await webauthn_factor.finish_authentication(
            state_token=token, session_id=5, credential=credential
        )


@pytest.mark.parametrize(
    ("identity_id", "args"),
    [
        (None, {"handle": None}),
        (None, {"handle": b"other"}),
        (17, {}),
        (42, {"credential_id": b"added-later"}),
        (42, {"origin": "https://other.example.com"}),
        (42, {"challenge": b"other"}),
        (42, {"counter": 7}),
        (42, {"flags": 1}),
    ],
)
@pytest.mark.anyio
async def test_rejected_assertions(webauthn_factor, webauthn_tables, identity_id, args):
    await seed_enrollment(
        webauthn_factor, webauthn_tables, args.get("credential_id", CREDENTIAL_ID)
    )
    token = await seed_state(webauthn_factor, webauthn_tables, identity_id=identity_id)
    with pytest.raises(InvalidAuthenticationException):
        await webauthn_factor.finish_authentication(
            state_token=token, session_id=5, credential=response(**args)
        )
    assert (
        await webauthn_factor.connection.scalar(
            sa.select(webauthn_tables[0].c.sign_count)
        )
        == 7
    )


@pytest.mark.parametrize(
    "mismatch", ["session_id", "ceremony", "factor_identifier", "rp_id", "expiry"]
)
@pytest.mark.anyio
async def test_state_binding(webauthn_factor, webauthn_tables, mismatch):
    token = await seed_state(
        webauthn_factor, webauthn_tables, expires_at=0 if mismatch == "expiry" else None
    )
    binding = {
        "session_id": 5,
        "ceremony": "authentication",
        "factor_identifier": webauthn_factor.identifier,
        "rp_id": RP,
    }
    if mismatch != "expiry":
        binding[mismatch] = "different"
    with pytest.raises(InvalidStateException):
        await webauthn_factor.state_service.consume(token, **binding)


@pytest.mark.parametrize("trusted", [True, False])
@pytest.mark.anyio
async def test_packed_attestation_roots(webauthn_factor, webauthn_tables, trusted):
    """Validate a signed packed attestation using the application's configured roots."""
    token = await seed_state(webauthn_factor, webauthn_tables, "enrollment", 42)
    credential = response(registration=True)
    fields = credential["response"]
    attestation = cbor2.loads(base64url_to_bytes(fields["attestationObject"]))
    signer = Ed25519PrivateKey.generate()
    now = datetime.datetime.now(datetime.UTC)

    def certificate(name, key, issuer_name, issuer_key, ca):
        return (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(issuer_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(
                x509.BasicConstraints(ca=ca, path_length=None), critical=True
            )
            .sign(issuer_key, None)
        )

    root_key = Ed25519PrivateKey.generate()
    root_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test root")])
    leaf_name = x509.Name(
        [x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test authenticator")]
    )
    leaf = certificate(leaf_name, signer, root_name, root_key, False)
    trusted_key = root_key if trusted else Ed25519PrivateKey.generate()
    root = certificate(root_name, trusted_key, root_name, trusted_key, True)
    webauthn_factor.attestation_roots = {
        AttestationFormat.PACKED: [root.public_bytes(Encoding.PEM)]
    }
    client_hash = hashlib.sha256(base64url_to_bytes(fields["clientDataJSON"])).digest()
    attestation.update(
        fmt="packed",
        attStmt={
            "alg": -8,
            "sig": signer.sign(attestation["authData"] + client_hash),
            "x5c": [leaf.public_bytes(Encoding.DER)],
        },
    )
    fields["attestationObject"] = bytes_to_base64url(cbor2.dumps(attestation))
    if trusted:
        enrollment = await webauthn_factor.finish_enrollment(
            state_token=token, session_id=5, credential=credential
        )
        assert enrollment.credential_id == CREDENTIAL_ID
    else:
        with pytest.raises(InvalidRegistrationException):
            await webauthn_factor.finish_enrollment(
                state_token=token, session_id=5, credential=credential
            )
