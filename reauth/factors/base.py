import abc
import typing

from reauth.amr import AuthenticationMethodReference
from reauth.logging import get_logger

logger = get_logger(__name__)

_ADVANCE_BY_VALUE_ERROR = "advance_by must be at least 1"


class FactorEnrollment(typing.Protocol):
    """
    Protocol for factor enrollment objects,
    which represent the state of an enrolled factor for a given identity.
    """

    id: typing.Any | None
    identity_id: typing.Any


class FactorBase[ENROLLMENT: FactorEnrollment](abc.ABC):
    """Base abstract class for all factor services."""

    AMR: typing.ClassVar[AuthenticationMethodReference]

    def __init__(self, *, identifier: str, step: int = 0, advance_by: int = 1) -> None:
        """
        Initialize the factor base.

        Args:
            identifier: A unique identifier for the factor,
                used for logging and API purposes.
            step: The authentication step at which this factor can be used.
                Factors are only available when the session's current step matches this value.
                Defaults to 0 (can be first factor).
            advance_by: The number of steps to advance the authentication session after
                this factor is successfully verified. Defaults to 1.

        Raises:
            ValueError: If advance_by is less than 1.
        """
        if advance_by < 1:
            raise ValueError(_ADVANCE_BY_VALUE_ERROR)

        logger.debug(
            "Factor initialized",
            extra={
                "identifier": identifier,
                "step": step,
                "advance_by": advance_by,
                "amr": str(self.AMR),
            },
        )
        self.identifier = identifier
        self.step = step
        self.advance_by = advance_by

    @abc.abstractmethod
    async def get_enrollments(self, identity_id: typing.Any) -> list[ENROLLMENT]:
        """
        Get the enrollments usable for authentication with this factor.

        Args:
            identity_id: The ID of the identity whose enrollments to get.

        Returns:
            The usable enrollments for the identity, or an empty list.

        Abstract: Implementation contract
            Scope the lookup to the requested identity and this configured factor.
            Acquire protection for matching records before reading and retain it
            until the transaction ends. Leave commit and rollback to the caller.
        """
        ...


class SingleEnrollmentFactorBase[ENROLLMENT: FactorEnrollment](FactorBase[ENROLLMENT]):
    """Base abstract class for factors with at most one enrollment per identity."""

    async def get_enrollments(self, identity_id: typing.Any) -> list[ENROLLMENT]:
        """Get the enrollments usable for authentication with this factor.

        Args:
            identity_id: The ID of the identity whose enrollment to get.

        Returns:
            A list with the usable enrollment, or an empty list.
        """
        enrollment = await self.get_enrollment(identity_id)
        return [] if enrollment is None else [enrollment]

    @abc.abstractmethod
    async def get_enrollment(self, identity_id: typing.Any) -> ENROLLMENT | None:
        """
        Get the enrollment usable for authentication with this factor.

        Args:
            identity_id: The ID of the identity whose enrollment to get.

        Returns:
            The usable enrollment for the identity, or None if there is none.

        Abstract: Implementation contract
            Scope the lookup to the requested identity and this configured factor.
            Acquire protection for a matching record before reading and retain it
            until the transaction ends. Leave commit and rollback to the caller.
        """
        ...
