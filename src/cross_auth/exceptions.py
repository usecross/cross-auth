class CrossAuthException(Exception):
    def __init__(self, error: str, error_description: str | None = None) -> None:
        self.error = error
        self.error_description = error_description
