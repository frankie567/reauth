class ReauthException(Exception):
    """Base exception for reauth."""

    def __init__(self, message: str | None = None) -> None:
        self.message = message
        super().__init__(message)


__all__ = ["ReauthException"]
