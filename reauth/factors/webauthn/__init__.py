"""WebAuthn registration and authentication using Duo's optional webauthn package."""

import abc
import collections.abc
import dataclasses
import typing

import webauthn
from webauthn.helpers import bytes_to_base64url, parse_authentication_credential_json
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AttestationFormat,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialRequestOptions,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from webauthn.registration.verify_registration_response import VerifiedRegistration

from reauth.amr import AuthenticationMethodReference
from reauth.factors.base import FactorBase
from reauth.factors.webauthn.state import WebAuthnException, WebAuthnStateService
from reauth.logging import get_logger

logger = get_logger(__name__)


@dataclasses.dataclass
class WebAuthnEnrollment:
    id: typing.Any | None
    identity_id: typing.Any
    rp_id: str
    factor_identifier: str
    credential_id: bytes
    public_key: bytes
    sign_count: int


class InvalidRegistrationException(WebAuthnException):
    """Registration failed verification."""


class AttestationRejectedException(WebAuthnException):
    """The application declined the attestation supplied at registration."""


class InvalidAuthenticationException(WebAuthnException):
    """The assertion is invalid or the credential is unavailable for this account."""


class WebAuthnFactor(FactorBase[WebAuthnEnrollment]):
    """Register and authenticate one or more credentials for each identity."""

    AMR: typing.ClassVar[AuthenticationMethodReference] = (
        AuthenticationMethodReference.POP
    )

    def __init__(
        self,
        *,
        rp_id: str,
        rp_name: str,
        allowed_origins: list[str],
        state_service: WebAuthnStateService,
        resident_key: ResidentKeyRequirement = ResidentKeyRequirement.PREFERRED,
        authenticator_attachment: AuthenticatorAttachment | None = None,
        user_verification: UserVerificationRequirement = UserVerificationRequirement.REQUIRED,
        attestation: AttestationConveyancePreference = AttestationConveyancePreference.NONE,
        attestation_roots: collections.abc.Mapping[AttestationFormat, list[bytes]]
        | None = None,
        identifier: str = "webauthn",
        step: int = 0,
        advance_by: int = 1,
    ) -> None:
        """Configure the RP and its credential selection and verification settings.

        Args:
            rp_id: Relying party domain shared by the registered credentials.
            rp_name: Relying party name shown during enrollment.
            allowed_origins: Exact browser origins accepted at both finish steps.
            state_service: Single-use ceremony state on the same transaction.
            resident_key: Discoverability preference for new credentials.
            authenticator_attachment: Optional platform or cross-platform selection.
            user_verification: Local user verification preference for both ceremonies.
            attestation: Attestation conveyance preference at registration.
            attestation_roots: PEM trust anchors by format, forwarded to Duo. Override
                accept_attestation to require specific evidence, including rejecting
                missing or self-attestation when manufacturer evidence is required.
            identifier: Factor identifier used to scope state and enrollments.
            step: Authentication session step at which the factor is available.
            advance_by: Number of steps advanced after authentication.

        Raises:
            ValueError: If the origin list is empty or a configuration value is invalid.
        """
        super().__init__(identifier=identifier, step=step, advance_by=advance_by)
        if not allowed_origins:
            message = "At least one WebAuthn origin is required"
            raise ValueError(message)
        self.rp_id = rp_id
        self.rp_name = rp_name
        self.allowed_origins = list(allowed_origins)
        self.state_service = state_service
        self.resident_key = ResidentKeyRequirement(resident_key)
        self.authenticator_attachment = (
            AuthenticatorAttachment(authenticator_attachment)
            if authenticator_attachment is not None
            else None
        )
        self.user_verification = UserVerificationRequirement(user_verification)
        self.attestation = AttestationConveyancePreference(attestation)
        self.attestation_roots = attestation_roots

    @abc.abstractmethod
    async def get_user_handle(self, identity_id: typing.Any) -> bytes:
        """Return the WebAuthn user handle for an application identity.

        Args:
            identity_id: The application's stable identifier for the account.

        Abstract: Implementation contract
            Supply 1–64 opaque bytes, unique per account and stable across all credentials
            and factors for the same RP. Exclude personally identifying information.
        """
        ...

    async def accept_attestation(self, registration: VerifiedRegistration) -> bool:
        """Decide whether to enroll a registration after Duo's verification succeeds.

        Args:
            registration: The verified registration to evaluate against the attestation policy.

        Returns:
            True to admit the credential. Override to enforce an attestation policy.
        """
        return True

    async def start_enrollment(
        self,
        *,
        identity_id: typing.Any,
        session_id: typing.Any,
        user_name: str,
        display_name: str | None = None,
    ) -> tuple[str, PublicKeyCredentialCreationOptions]:
        """Start registration for the account authorized by the initiating session.

        Args:
            identity_id: The application identity that will own the credential.
            session_id: The ID of the session authorizing enrollment.
            user_name: The account name shown in the authenticator's account selector.
            display_name: An optional human-readable name for the account.

        Returns:
            The opaque state token and browser creation options.

        Raises:
            ValueError: If the identity is missing or its user handle is invalid.
        """
        logger.debug("WebAuthn enrollment started", extra={"identity_id": identity_id})
        if identity_id is None:
            message = "Enrollment requires a known identity"
            raise ValueError(message)
        handle = await self.get_user_handle(identity_id)
        if not isinstance(handle, bytes) or not 1 <= len(handle) <= 64:
            message = "WebAuthn user handle must contain 1 to 64 bytes"
            raise ValueError(message)
        enrollments = await self.get_enrollments(identity_id)
        options = webauthn.generate_registration_options(
            rp_id=self.rp_id,
            rp_name=self.rp_name,
            user_name=user_name,
            user_id=handle,
            user_display_name=display_name,
            attestation=self.attestation,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=self.resident_key,
                user_verification=self.user_verification,
                authenticator_attachment=self.authenticator_attachment,
            ),
            exclude_credentials=[
                PublicKeyCredentialDescriptor(id=e.credential_id) for e in enrollments
            ],
        )
        token, _ = await self.state_service.create(
            rp_id=self.rp_id,
            factor_identifier=self.identifier,
            ceremony="enrollment",
            session_id=session_id,
            identity_id=identity_id,
            challenge=options.challenge,
        )
        return token, options

    async def finish_enrollment(
        self,
        *,
        state_token: str,
        session_id: typing.Any,
        credential: str | dict[str, typing.Any],
    ) -> WebAuthnEnrollment:
        """Verify a browser registration, apply the application policy and enroll it.

        Catch InvalidRegistrationException or AttestationRejectedException inside
        the caller's transaction and commit the state deletion before reporting
        the failure. If a concurrent registration inserts the same credential after
        the duplicate check, the storage adapter's integrity error propagates.
        Roll back the transaction in that case.

        Args:
            state_token: The opaque token returned by start_enrollment.
            session_id: The current session's ID, which must match the initiating session.
            credential: The browser's registration response as a JSON string or dictionary.

        Returns:
            The newly persisted enrollment.

        Raises:
            InvalidRegistrationException: If verification fails or the duplicate check
                finds an existing enrollment.
                State consumption is pending in the caller's transaction and must
                be committed despite this exception.
            AttestationRejectedException: If the application declines the registration.
                State consumption is pending in the caller's transaction and must
                be committed despite this exception.
        """
        state = await self.state_service.consume(
            state_token,
            rp_id=self.rp_id,
            factor_identifier=self.identifier,
            ceremony="enrollment",
            session_id=session_id,
        )
        try:
            registration = webauthn.verify_registration_response(
                credential=credential,
                expected_challenge=state.challenge,
                expected_rp_id=self.rp_id,
                expected_origin=self.allowed_origins,
                require_user_verification=self.user_verification
                == UserVerificationRequirement.REQUIRED,
                pem_root_certs_bytes_by_fmt=self.attestation_roots,
            )
        except Exception as error:
            logger.warning(
                "WebAuthn registration verification failed",
                extra={"identity_id": state.identity_id},
            )
            raise InvalidRegistrationException() from error
        if len(registration.credential_id) > 1023 or await self.credential_exists(
            registration.credential_id
        ):
            logger.warning(
                "WebAuthn credential ID invalid or already enrolled",
                extra={"identity_id": state.identity_id},
            )
            raise InvalidRegistrationException()
        if not await self.accept_attestation(registration):
            logger.warning(
                "WebAuthn attestation rejected",
                extra={"identity_id": state.identity_id},
            )
            raise AttestationRejectedException()
        enrollment = WebAuthnEnrollment(
            id=None,
            identity_id=state.identity_id,
            rp_id=self.rp_id,
            factor_identifier=self.identifier,
            credential_id=registration.credential_id,
            public_key=registration.credential_public_key,
            sign_count=registration.sign_count,
        )
        enrollment.id = await self.insert(enrollment)
        logger.info(
            "WebAuthn credential enrolled",
            extra={
                "identity_id": enrollment.identity_id,
                "enrollment_id": enrollment.id,
            },
        )
        return enrollment

    async def start_authentication(
        self,
        *,
        session_id: typing.Any,
        identity_id: typing.Any | None = None,
    ) -> tuple[str, PublicKeyCredentialRequestOptions]:
        """Start an account-bound or discoverable authentication ceremony.

        Args:
            session_id: The ID of the session requesting authentication.
            identity_id: The account to authenticate. Omit to let the user select a
                discoverable credential.

        Returns:
            The opaque state token and browser request options.

        Raises:
            InvalidAuthenticationException: If the known identity has no eligible credential.
        """
        logger.debug(
            "WebAuthn authentication started", extra={"identity_id": identity_id}
        )
        allowed = None
        if identity_id is not None:
            enrollments = await self.get_enrollments(identity_id)
            if not enrollments:
                logger.warning(
                    "WebAuthn identity has no usable enrollment",
                    extra={"identity_id": identity_id},
                )
                raise InvalidAuthenticationException()
            allowed = [
                PublicKeyCredentialDescriptor(id=e.credential_id) for e in enrollments
            ]
        options = webauthn.generate_authentication_options(
            rp_id=self.rp_id,
            allow_credentials=allowed,
            user_verification=self.user_verification,
        )
        options.allow_credentials = allowed
        token, _ = await self.state_service.create(
            rp_id=self.rp_id,
            factor_identifier=self.identifier,
            ceremony="authentication",
            session_id=session_id,
            identity_id=identity_id,
            challenge=options.challenge,
            allowed_credential_ids=[bytes_to_base64url(c.id) for c in allowed]
            if allowed
            else None,
        )
        return token, options

    async def finish_authentication(
        self,
        *,
        state_token: str,
        session_id: typing.Any,
        credential: str | dict[str, typing.Any],
    ) -> WebAuthnEnrollment:
        """Verify the assertion and return its owning enrollment for session advancement.

        Catch InvalidAuthenticationException inside the caller's transaction and
        commit the state deletion before reporting the failure.

        Args:
            state_token: The opaque token returned by start_authentication.
            session_id: The current session's ID, which must match the initiating session.
            credential: The browser's assertion response as a JSON string or dictionary.

        Returns:
            The verified enrollment with its updated signature counter.

        Raises:
            InvalidAuthenticationException: If the assertion or account binding is invalid.
                State consumption is pending in the caller's transaction and must
                be committed despite this exception.
        """
        state = await self.state_service.consume(
            state_token,
            rp_id=self.rp_id,
            factor_identifier=self.identifier,
            ceremony="authentication",
            session_id=session_id,
        )
        try:
            assertion = parse_authentication_credential_json(credential)
        except Exception as error:
            logger.warning(
                "Malformed WebAuthn assertion", extra={"identity_id": state.identity_id}
            )
            raise InvalidAuthenticationException() from error
        enrollment = await self.get_by_credential_id(assertion.raw_id)
        if enrollment is None:
            logger.warning(
                "Unknown WebAuthn credential", extra={"identity_id": state.identity_id}
            )
            raise InvalidAuthenticationException()
        if state.identity_id is not None and (
            enrollment.identity_id != state.identity_id
            or assertion.id not in (state.allowed_credential_ids or ())
        ):
            logger.warning(
                "WebAuthn credential unavailable for this ceremony",
                extra={"identity_id": state.identity_id},
            )
            raise InvalidAuthenticationException()
        handle = assertion.response.user_handle
        if state.identity_id is None and handle is None:
            logger.warning(
                "Missing WebAuthn user handle",
                extra={"identity_id": enrollment.identity_id},
            )
            raise InvalidAuthenticationException()
        if handle is not None and handle != await self.get_user_handle(
            enrollment.identity_id
        ):
            logger.warning(
                "WebAuthn user handle mismatch",
                extra={"identity_id": enrollment.identity_id},
            )
            raise InvalidAuthenticationException()
        try:
            verified = webauthn.verify_authentication_response(
                credential=assertion,
                expected_challenge=state.challenge,
                expected_rp_id=self.rp_id,
                expected_origin=self.allowed_origins,
                require_user_verification=self.user_verification
                == UserVerificationRequirement.REQUIRED,
                credential_public_key=enrollment.public_key,
                credential_current_sign_count=enrollment.sign_count,
            )
        except Exception as error:
            logger.warning(
                "WebAuthn assertion verification failed",
                extra={"identity_id": enrollment.identity_id},
            )
            raise InvalidAuthenticationException() from error
        enrollment.sign_count = verified.new_sign_count
        await self.update(enrollment)
        logger.info(
            "WebAuthn authentication succeeded",
            extra={
                "identity_id": enrollment.identity_id,
                "enrollment_id": enrollment.id,
            },
        )
        return enrollment

    @abc.abstractmethod
    async def credential_exists(self, credential_id: bytes) -> bool:
        """Check whether a credential is already registered with this relying party.

        Args:
            credential_id: The raw credential ID supplied by the authenticator.

        Returns:
            True if any enrollment for this relying party uses the credential ID.

        Abstract: Implementation contract
            Match the configured RP and exact credential ID across all identities and
            factors. This precheck does not reserve the ID for a subsequent insert.
            Leave commit and rollback to the caller.
        """
        ...

    @abc.abstractmethod
    async def get_by_credential_id(
        self, credential_id: bytes
    ) -> WebAuthnEnrollment | None:
        """Find the credential eligible for this configured factor.

        Args:
            credential_id: The raw credential ID supplied by the authenticator.

        Abstract: Implementation contract
            Match the RP, factor identifier and exact credential ID. Acquire protection before
            reading and retain it through the transaction. Leave commit and rollback to the caller.
        """
        ...

    @abc.abstractmethod
    async def insert(self, enrollment: WebAuthnEnrollment) -> typing.Any:
        """Insert a verified credential and return its record ID.

        Args:
            enrollment: The verified enrollment to persist.

        Abstract: Implementation contract
            Enforce credential ID uniqueness across all accounts and factors within the RP.
            Persist the enrollment atomically. Leave commit and rollback to the caller.
        """
        ...

    @abc.abstractmethod
    async def update(self, enrollment: WebAuthnEnrollment) -> None:
        """Persist the signature counter for the verified credential.

        Args:
            enrollment: The existing enrollment with its updated signature counter.

        Abstract: Implementation contract
            Update the protected enrollment by ID in the same transaction and retain
            protection until it ends. Leave commit and rollback to the caller.
        """
        ...

    @abc.abstractmethod
    async def delete(self, enrollment: WebAuthnEnrollment) -> None:
        """Revoke an enrollment.

        Args:
            enrollment: The credential enrollment to revoke.

        Abstract: Implementation contract
            Delete the supplied enrollment by ID in the transaction protecting it.
            Leave commit and rollback to the caller.
        """
        ...


__all__ = [
    "AttestationConveyancePreference",
    "AttestationFormat",
    "AttestationRejectedException",
    "AuthenticatorAttachment",
    "AuthenticatorSelectionCriteria",
    "InvalidAuthenticationException",
    "InvalidRegistrationException",
    "PublicKeyCredentialCreationOptions",
    "PublicKeyCredentialDescriptor",
    "PublicKeyCredentialRequestOptions",
    "ResidentKeyRequirement",
    "UserVerificationRequirement",
    "VerifiedRegistration",
    "WebAuthnEnrollment",
    "WebAuthnException",
    "WebAuthnFactor",
    "WebAuthnStateService",
]
