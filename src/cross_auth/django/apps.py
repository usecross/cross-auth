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

        user_logged_in.connect(
            _start_sign_in, dispatch_uid="cross_auth.sessions.start_sign_in"
        )
