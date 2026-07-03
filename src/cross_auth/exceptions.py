class CrossAuthException(Exception):
    def __init__(
        self,
        error: str,
        error_description: str | None = None,
        status_code: int = 400,
    ) -> None:
        self.error = error
        self.error_description = error_description
        self.status_code = status_code


class InvalidCursorError(ValueError):
    """Raised when a session pagination cursor is malformed, tampered with, or
    was created under a different ordering than the current request.

    Custom ``SessionStorage`` implementations should raise this from
    ``list_for_user`` too, so applications can map bad cursors to a 400
    response without caring which storage backend is configured."""
