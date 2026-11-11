"""Exceptions raised by the SQLAlchemy integration."""

import sqlalchemy.exc

from reauth.exceptions import ReauthException


class ReauthSQLAlchemyException(ReauthException):
    """Base exception for the SQLAlchemy integration."""


class MissingTransactionException(ReauthSQLAlchemyException):
    """Raised when a connection has no active caller-owned transaction."""


class EnrollmentAlreadyExistsException(
    sqlalchemy.exc.IntegrityError, ReauthSQLAlchemyException
):
    """Raised when an identity already has an enrollment for the configured factor."""
