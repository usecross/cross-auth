from __future__ import annotations

from typing import Any

from django.core import checks
from django.core.exceptions import ImproperlyConfigured

from .conf import get_settings


@checks.register(checks.Tags.compatibility)
def check_settings(**kwargs: Any) -> list[checks.CheckMessage]:
    try:
        get_settings()
    except (ImproperlyConfigured, ImportError) as error:
        return [checks.Error(str(error), id="cross_auth.E001")]
    return []
