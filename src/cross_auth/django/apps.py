from django.apps import AppConfig


class CrossAuthConfig(AppConfig):
    name = "cross_auth.django"
    # The package name would otherwise give this app the label "django".
    label = "cross_auth"
    verbose_name = "Cross Auth"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self) -> None:
        from django.contrib.auth.signals import user_logged_in

        from . import checks  # noqa: F401  # registers system checks
        from .sessions import _start_sign_in

        from .mfa import _guard, _update_last_login

        user_logged_in.connect(
            _start_sign_in, dispatch_uid="cross_auth.sessions.start_sign_in"
        )
        # The 2FA guard holds back logins that need a second factor (it does
        # nothing without CROSS_AUTH["MFA"]). last_login then waits for the
        # verify page: Django's own receiver is swapped for one that skips
        # held-back logins, which must run after the guard.
        user_logged_in.connect(_guard, dispatch_uid="cross_auth.mfa.guard")
        if user_logged_in.disconnect(dispatch_uid="update_last_login"):
            user_logged_in.connect(
                _update_last_login, dispatch_uid="cross_auth.mfa.update_last_login"
            )
