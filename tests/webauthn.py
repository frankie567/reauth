import dataclasses
import hashlib
import json
from collections.abc import AsyncIterator

import cbor2
import pytest
import sqlalchemy as sa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine
from webauthn.helpers import bytes_to_base64url

from reauth.factors.webauthn import (
    ResidentKeyRequirement,
    WebAuthnEnrollment,
)
from reauth.factors.webauthn.state import Ceremony, WebAuthnState
from reauth.integrations.sqlalchemy.webauthn import (
    SQLAlchemyWebAuthnFactor,
    SQLAlchemyWebAuthnStateService,
    create_webauthn_enrollment_table,
    create_webauthn_state_table,
)
from reauth.timestamp import get_current_timestamp
from reauth.tokens import (
    ChecksummedTokenProvider,
    HMACTokenVerifier,
)

RP = "example.com"
ORIGIN = "https://example.com"
CHALLENGE = b"c" * 32
CREDENTIAL_ID = b"laptop"
KEY = Ed25519PrivateKey.generate()
PUBLIC_KEY = cbor2.dumps({1: 1, 3: -8, -1: 6, -2: KEY.public_key().public_bytes_raw()})


class Factor(SQLAlchemyWebAuthnFactor):
    async def get_user_handle(self, identity_id: int) -> bytes:
        return identity_id.to_bytes(16)


@pytest.fixture
async def webauthn_tables(
    sqlalchemy_integration_engine: AsyncEngine,
) -> AsyncIterator[tuple[sa.Table, sa.Table]]:
    metadata = sa.MetaData()
    enrollments = create_webauthn_enrollment_table(metadata)
    states = create_webauthn_state_table(metadata)
    async with sqlalchemy_integration_engine.begin() as connection:
        await connection.run_sync(metadata.create_all)
    try:
        yield enrollments, states
    finally:
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.run_sync(metadata.drop_all)


def make_factor(
    connection: AsyncConnection, tables: tuple[sa.Table, sa.Table]
) -> Factor:
    enrollments, states = tables
    provider = ChecksummedTokenProvider(
        prefix="webauthn_",
        verifier=HMACTokenVerifier(current_key_id="test", keys={"test": b"k" * 32}),
    )
    service = SQLAlchemyWebAuthnStateService(
        connection, states, token_provider=provider
    )
    return Factor(
        connection,
        enrollments,
        rp_id=RP,
        rp_name="Example",
        allowed_origins=[ORIGIN],
        resident_key=ResidentKeyRequirement.REQUIRED,
        state_service=service,
    )


@pytest.fixture
async def webauthn_factor(
    sqlalchemy_integration_engine: AsyncEngine,
    webauthn_tables: tuple[sa.Table, sa.Table],
) -> AsyncIterator[Factor]:
    async with sqlalchemy_integration_engine.begin() as connection:
        yield make_factor(connection, webauthn_tables)


async def seed_state(
    factor: Factor,
    tables: tuple[sa.Table, sa.Table],
    ceremony: Ceremony = "authentication",
    identity_id: int | None = None,
    expires_at: int | None = None,
) -> str:
    token = await factor.state_service.token_provider.generate()
    state = WebAuthnState(
        1,
        token.identifier,
        token.verifier,
        RP,
        factor.identifier,
        ceremony,
        5,
        identity_id,
        CHALLENGE,
        [bytes_to_base64url(CREDENTIAL_ID)]
        if identity_id is not None and ceremony == "authentication"
        else None,
        expires_at if expires_at is not None else get_current_timestamp() + 300,
    )
    await factor.connection.execute(
        tables[1].insert().values(**dataclasses.asdict(state))
    )
    return token.token


async def seed_enrollment(
    factor: Factor,
    tables: tuple[sa.Table, sa.Table],
    credential_id: bytes = CREDENTIAL_ID,
) -> None:
    enrollment = WebAuthnEnrollment(
        None, 42, RP, factor.identifier, credential_id, PUBLIC_KEY, 7
    )
    values = dataclasses.asdict(enrollment)
    del values["id"]
    await factor.connection.execute(tables[0].insert().values(**values))


def response(
    *,
    registration: bool = False,
    handle: bytes | None = (42).to_bytes(16),
    challenge: bytes = CHALLENGE,
    origin: str = ORIGIN,
    counter: int = 8,
    flags: int = 5,
    credential_id: bytes = CREDENTIAL_ID,
) -> dict[str, str | dict[str, str]]:
    client = json.dumps(
        {
            "type": "webauthn.create" if registration else "webauthn.get",
            "origin": origin,
            "challenge": bytes_to_base64url(challenge),
        }
    ).encode()
    auth_data = (
        hashlib.sha256(RP.encode()).digest()
        + bytes([flags | 64 if registration else flags])
        + counter.to_bytes(4)
    )
    fields = {"clientDataJSON": bytes_to_base64url(client)}
    if registration:
        auth_data += (
            bytes(16) + len(credential_id).to_bytes(2) + credential_id + PUBLIC_KEY
        )
        fields["attestationObject"] = bytes_to_base64url(
            cbor2.dumps({"fmt": "none", "authData": auth_data, "attStmt": {}})
        )
    else:
        fields["authenticatorData"] = bytes_to_base64url(auth_data)
        fields["signature"] = bytes_to_base64url(
            KEY.sign(auth_data + hashlib.sha256(client).digest())
        )
        if handle is not None:
            fields["userHandle"] = bytes_to_base64url(handle)
    return {
        "id": bytes_to_base64url(credential_id),
        "rawId": bytes_to_base64url(credential_id),
        "type": "public-key",
        "response": fields,
    }
