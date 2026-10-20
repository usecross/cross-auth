from django.apps import AppConfig


class TestAppConfig(AppConfig):
    name = "tests.django.testapp"
    label = "testapp"

    def ready(self) -> None:
        from . import signals  # noqa: F401  # connects the receivers
