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
    async def get_enrollment(self, identity_id: typing.Any) -> ENROLLMENT | None:
        """
        Get the enrollment information for a given identity.

        Args:
            identity_id: The ID of the identity to get the factor configuration for.

        Returns:
            The enrollment information for the factor,
            or None if the factor is not enrolled for the identity.
        """
        ...
