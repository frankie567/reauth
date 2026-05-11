import abc
import typing

from ..amr import AuthenticationMethodReference


class FactorBase(abc.ABC):
    """Base abstract class for all factor services."""

    AMR: typing.ClassVar[AuthenticationMethodReference]

    def __init__(self, *, min_prior_factors: int = 0) -> None:
        """
        Initialize the factor base.

        Args:
            min_prior_factors: Minimum number of prior factors that must complete
                before this factor can be used. Defaults to 0 (can be first factor).
        """
        self.min_prior_factors = min_prior_factors
