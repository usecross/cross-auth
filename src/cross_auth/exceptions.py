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
