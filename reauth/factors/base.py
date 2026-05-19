import abc
import typing

from reauth.amr import AuthenticationMethodReference
from reauth.logging import get_logger

logger = get_logger(__name__)


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

    def __init__(self, *, identifier: str, step: int = 0) -> None:
        """
        Initialize the factor base.

        Args:
            identifier: A unique identifier for the factor,
                used for logging and API purposes.
            step: The authentication step at which this factor can be used.
                Factors are only available when the session's current step matches this value.
                Defaults to 0 (can be first factor).
        """
        logger.debug(
            "Factor initialized",
            extra={
                "identifier": identifier,
                "step": step,
                "amr": str(self.AMR),
            },
        )
        self.identifier = identifier
        self.step = step

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
