"""Exceptions raised by the SQLAlchemy integration."""

from reauth.exceptions import ReauthException


class ReauthSQLAlchemyException(ReauthException):
    """Base exception for the SQLAlchemy integration."""


class MissingTransactionException(ReauthSQLAlchemyException):
    """Raised when a connection has no active caller-owned transaction."""


class EnrollmentAlreadyExistsException(ReauthSQLAlchemyException):
    """Raised when an identity already has an enrollment for the configured factor."""
