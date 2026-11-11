"""Shared SQLAlchemy adapter behavior."""

import sqlalchemy.ext.asyncio

from reauth.integrations.sqlalchemy.exceptions import MissingTransactionException


class TransactionMixin:
    """Require a caller-owned transaction on the adapter's connection."""

    connection: sqlalchemy.ext.asyncio.AsyncConnection

    def _require_transaction(self) -> None:
        if not self.connection.in_transaction():
            raise MissingTransactionException()
