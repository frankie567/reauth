"""Logging configuration for reauth."""

import logging


def get_logger(name: str) -> logging.Logger:
    """Get a logger for a reauth module.

    Args:
        name: The logger name, typically __name__.

    Returns:
        A configured logger instance.
    """
    return logging.getLogger(name)


def configure_logger(
    *,
    level: int = logging.WARNING,
    handler: logging.Handler | None = None,
) -> logging.Logger:
    """Configure the reauth logger with a handler.

    This is an optional helper for library users to quickly set up logging.
    Users can also configure logging manually using standard logging configuration.

    Args:
        level: The logging level (default: WARNING).
        handler: A logging handler (default: StreamHandler to stderr).

    Returns:
        The configured reauth logger.

    Example:
        >>> from reauth.logging import configure_logger
        >>> configure_logger(level=logging.DEBUG)
    """
    logger = logging.getLogger("reauth")
    logger.setLevel(level)

    if handler is None:
        handler = logging.StreamHandler()
        handler.setLevel(level)
        handler.setFormatter(
            logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        )

    logger.addHandler(handler)
    return logger


def _ensure_null_handler() -> None:
    """Ensure the reauth logger has a NullHandler to prevent warnings."""
    logger = logging.getLogger("reauth")
    if not logger.handlers:
        logger.addHandler(logging.NullHandler())


# Ensure null handler is added when this module is imported
_ensure_null_handler()
