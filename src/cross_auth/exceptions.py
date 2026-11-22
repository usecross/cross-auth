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


class MFARequired(CrossAuthException):
    """A sign-in passed its first factor and now needs a second one.

    Nothing was issued. ``challenge`` is the single-use token to finish the
    sign-in with, through ``CrossAuth.complete_mfa_login`` or ``verify_mfa``;
    it is ``None`` until the layer that started the sign-in stores one.
    ``methods`` lists what the user can answer with: ``"totp"`` and, when
    they have codes left, ``"recovery_code"``.
    """

    def __init__(
        self,
        *,
        user_id: str,
        login_method: str | None,
        methods: list[str],
        challenge: str | None = None,
    ) -> None:
        super().__init__(
            "mfa_required",
            "This sign-in needs a second factor",
            status_code=401,
        )
        self.user_id = user_id
        self.login_method = login_method
        self.methods = methods
        self.challenge = challenge
