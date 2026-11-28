"""Settings for the Django integration, read from ``settings.CROSS_AUTH``."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import timedelta
from functools import cache
from typing import Any, Protocol, cast

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import UserManager
from django.core.exceptions import ImproperlyConfigured
from django.core.signals import setting_changed
from django.utils.module_loading import import_string

from cross_auth._clients import ClientResolver
from cross_auth._config import AccountLinkingConfig
from cross_auth._mfa import MFAConfig, resolve_config
from cross_auth.social_providers.oauth import OAuth2Provider


class UserFactory(Protocol):
    """Creates the native user for a first provider sign-in.

    Runs inside the transaction that also stores the user's first identity.
    All writes must use the supplied ``using`` alias (via ``db_manager``/``using``),
    including related rows. Return a saved AUTH_USER_MODEL on that database.
    A misrouted write cannot be rolled back by this transaction; the returned
    user's database is validated, but related writes remain the factory's
    responsibility. Do not call external services; send notifications from a
    ``user_created`` receiver instead. ``email`` is normalized; ``extra_fields``
    is empty.
    """

    def __call__(
        self,
        *,
        email: str,
        user_info: Mapping[str, Any],
        extra_fields: Mapping[str, Any],
        using: str,
    ) -> AbstractBaseUser: ...


def create_user(
    *,
    email: str,
    user_info: Mapping[str, Any],
    extra_fields: Mapping[str, Any],
    using: str,
) -> AbstractBaseUser:
    """Default factory for models managed by Django's ``UserManager``.

    Uses the email as the username and leaves the user without a usable
    password. Other user models need ``CROSS_AUTH["CREATE_USER"]``.
    """
    manager = get_user_model()._default_manager.db_manager(using)
    if not isinstance(manager, UserManager):
        raise ImproperlyConfigured(
            "The default Cross Auth user factory needs a user model managed by "
            "django.contrib.auth.models.UserManager; set CROSS_AUTH['CREATE_USER']"
        )
    user = manager.create_user(email, email=email, **extra_fields)
    if not isinstance(user, AbstractBaseUser):
        raise TypeError("UserManager.create_user did not return a user")
    return user


@dataclass(frozen=True)
class OAuthServerSettings:
    """``CROSS_AUTH["OAUTH_SERVER"]``: sign-in for your own SPA and native clients."""

    # Looks up a registered client by its ID; None for an unknown one.
    get_client: ClientResolver
    # How long a new bearer token lasts, in seconds.
    token_max_age: int
    # How old, in seconds, a token's session gets before a request that uses
    # it extends it by token_max_age. None: a token ends token_max_age after
    # it was issued, however much it is used.
    token_update_age: int | None


@dataclass(frozen=True)
class ProviderTokenSettings:
    """``CROSS_AUTH["PROVIDER_TOKENS"]``: keep providers' tokens, encrypted."""

    # Turns a token into the text stored in its place.
    encrypt: Callable[[str], str]
    # Turns stored text back into the token, or returns None when it cannot,
    # for example after a key change. The token then counts as missing.
    decrypt: Callable[[str], str | None]


# Decides whether a sign-in needs 2FA: the native user and the provider ID
# of a Cross Auth sign-in, or None for Django's own logins.
DjangoRequiresMFA = Callable[[AbstractBaseUser, "str | None"], bool]


@dataclass(frozen=True)
class MFASettings:
    """``CROSS_AUTH["MFA"]``: two-factor authentication."""

    # Core's config['mfa'], without the verify URL and the encryption keys,
    # which are filled in for each request.
    config: MFAConfig
    # None: core's default rule, with require_for_providers.
    requires_mfa: DjangoRequiresMFA | None
    # Whether config has the application's own encrypt and decrypt.
    custom_encryption: bool
    # The application's own verify page: a URL name or path. None: the
    # library's cross_auth:mfa_verify page.
    verify_url: str | None = None


@dataclass(frozen=True)
class CrossAuthSettings:
    providers: Mapping[str, OAuth2Provider]
    create_user: UserFactory
    # Whether users can sign in with their Django password. When True, a
    # usable password counts as another way to sign in, so the last provider
    # identity can be disconnected.
    password_login: bool
    account_linking: AccountLinkingConfig
    require_verified_email: bool
    # Public origin used for provider callback URLs instead of the request's.
    base_url: str | None
    # How stale cross_auth.django.sessions lets a session's last_activity get
    # before a request that does not save the session updates it.
    session_activity_interval: timedelta
    # Whether cross_auth.django.sessions stores the request's REMOTE_ADDR.
    session_store_ip: bool
    # None: the authorize, token and logout views answer "not found".
    oauth_server: OAuthServerSettings | None
    # None: providers' access and refresh tokens are not stored.
    provider_tokens: ProviderTokenSettings | None
    # None: two-factor authentication is off.
    mfa: MFASettings | None = None


_KNOWN_KEYS = frozenset(
    {
        "PROVIDERS",
        "CREATE_USER",
        "PASSWORD_LOGIN",
        "ACCOUNT_LINKING",
        "REQUIRE_VERIFIED_EMAIL",
        "BASE_URL",
        "SESSION_ACTIVITY_INTERVAL",
        "SESSION_STORE_IP",
        "OAUTH_SERVER",
        "PROVIDER_TOKENS",
        "MFA",
    }
)
_ACCOUNT_LINKING_KEYS = frozenset({"enabled", "allow_different_emails"})
_OAUTH_SERVER_KEYS = frozenset({"get_client", "token_max_age", "token_update_age"})
_PROVIDER_TOKEN_KEYS = ("encrypt", "decrypt")
# A day, like Cross Auth's sessions elsewhere.
_DEFAULT_TOKEN_MAX_AGE = 24 * 60 * 60
# Ten years. A token's expiry is now plus its age, which must stay a date
# that Python and the database can hold.
_MAX_TOKEN_AGE = 10 * 365 * 24 * 60 * 60
# A year. Sessions compare their last_activity with now minus the interval,
# which must stay a date that Python and the database can hold.
_MAX_SESSION_ACTIVITY_INTERVAL = 365 * 24 * 60 * 60


def _bool(
    raw: Mapping[Any, object], key: str, default: bool, *, prefix: str = ""
) -> bool:
    value = raw.get(key, default)
    if not isinstance(value, bool):
        raise ImproperlyConfigured(f"CROSS_AUTH{prefix}['{key}'] must be a bool")
    return value


def _seconds(
    raw: Mapping[str, object], key: str, default: int, *, maximum: int
) -> timedelta:
    value = raw.get(key, default)
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= maximum
    ):
        raise ImproperlyConfigured(
            f"CROSS_AUTH['{key}'] must be a number of seconds, an int from 0 to "
            f"{maximum}"
        )
    return timedelta(seconds=value)


def _providers(value: object) -> dict[str, OAuth2Provider]:
    if not isinstance(value, (list, tuple)):
        raise ImproperlyConfigured("CROSS_AUTH['PROVIDERS'] must be a list")
    providers: dict[str, OAuth2Provider] = {}
    for provider in value:
        if not isinstance(provider, OAuth2Provider):
            raise ImproperlyConfigured(
                "CROSS_AUTH['PROVIDERS'] must contain provider instances such as "
                "GoogleProvider(...)"
            )
        if provider.id in providers:
            raise ImproperlyConfigured(
                f"CROSS_AUTH['PROVIDERS'] lists {provider.id!r} more than once"
            )
        providers[provider.id] = provider
    return providers


def _account_linking(value: object) -> AccountLinkingConfig:
    if not isinstance(value, Mapping):
        raise ImproperlyConfigured("CROSS_AUTH['ACCOUNT_LINKING'] must be a dict")
    unknown = set(value) - _ACCOUNT_LINKING_KEYS
    if unknown:
        # allow_shared_connections is not offered: the schema gives each
        # identity exactly one owner.
        raise ImproperlyConfigured(
            "Unsupported CROSS_AUTH['ACCOUNT_LINKING'] key(s): "
            + ", ".join(sorted(unknown))
        )
    return AccountLinkingConfig(
        enabled=_bool(value, "enabled", False, prefix="['ACCOUNT_LINKING']"),
        allow_different_emails=_bool(
            value, "allow_different_emails", False, prefix="['ACCOUNT_LINKING']"
        ),
    )


def _token_age(
    raw: Mapping[Any, object], key: str, default: int | None, *, minimum: int
) -> int | None:
    value = raw.get(key, default)
    if value is None and default is None:
        return None
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= _MAX_TOKEN_AGE
    ):
        raise ImproperlyConfigured(
            f"CROSS_AUTH['OAUTH_SERVER']['{key}'] must be a number of seconds, "
            f"an int from {minimum} to {_MAX_TOKEN_AGE}"
            + (" or None" if default is None else "")
        )
    return value


def _oauth_server(value: object) -> OAuthServerSettings | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ImproperlyConfigured("CROSS_AUTH['OAUTH_SERVER'] must be a dict")
    if not settings.USE_TZ:
        # Core compares a token's times with the current time in UTC; without
        # time zone support Django hands back naive local times.
        raise ImproperlyConfigured("CROSS_AUTH['OAUTH_SERVER'] needs USE_TZ = True")

    return _oauth_server_settings(value)


def _oauth_server_settings(raw: Mapping[Any, object]) -> OAuthServerSettings:
    unknown = set(raw) - _OAUTH_SERVER_KEYS
    if unknown:
        raise ImproperlyConfigured(
            "Unsupported CROSS_AUTH['OAUTH_SERVER'] key(s): "
            + ", ".join(sorted(map(str, unknown)))
        )

    path = raw.get("get_client")
    if not isinstance(path, str):
        raise ImproperlyConfigured(
            "CROSS_AUTH['OAUTH_SERVER']['get_client'] must be the dotted path of "
            "a function that returns the OAuthClient with a client ID, or None"
        )
    get_client = import_string(path)
    if not callable(get_client):
        raise ImproperlyConfigured(
            f"CROSS_AUTH['OAUTH_SERVER']['get_client'] {path!r} is not callable"
        )

    token_max_age = _token_age(raw, "token_max_age", _DEFAULT_TOKEN_MAX_AGE, minimum=1)
    assert token_max_age is not None

    return OAuthServerSettings(
        get_client=get_client,
        token_max_age=token_max_age,
        token_update_age=_token_age(raw, "token_update_age", None, minimum=0),
    )


def _provider_tokens(value: object) -> ProviderTokenSettings | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ImproperlyConfigured("CROSS_AUTH['PROVIDER_TOKENS'] must be a dict")
    if set(value) != set(_PROVIDER_TOKEN_KEYS):
        raise ImproperlyConfigured(
            "CROSS_AUTH['PROVIDER_TOKENS'] needs exactly the keys 'encrypt' and "
            "'decrypt'"
        )
    if not settings.USE_TZ:
        # Core passes token expiry times as aware datetimes.
        raise ImproperlyConfigured("CROSS_AUTH['PROVIDER_TOKENS'] needs USE_TZ = True")
    return _provider_token_settings(value)


def _provider_token_settings(raw: Mapping[Any, object]) -> ProviderTokenSettings:
    return ProviderTokenSettings(
        encrypt=_token_function(raw, "encrypt"),
        decrypt=_token_function(raw, "decrypt"),
    )


def _token_function(raw: Mapping[Any, object], key: str) -> Callable[[str], Any]:
    path = raw[key]
    if not isinstance(path, str):
        raise ImproperlyConfigured(
            f"CROSS_AUTH['PROVIDER_TOKENS']['{key}'] must be the dotted path of a "
            "function"
        )
    function = import_string(path)
    if not callable(function):
        raise ImproperlyConfigured(
            f"CROSS_AUTH['PROVIDER_TOKENS']['{key}'] {path!r} is not callable"
        )
    return function


_MFA_PATH_KEYS = ("encrypt", "decrypt", "requires_mfa")
_MFA_KEYS = frozenset(
    {
        "issuer",
        "require_for_providers",
        "allow_unverified_email",
        "challenge_ttl",
        "max_attempts",
        "lockout_failures",
        "lockout_seconds",
        "reauthentication_max_age",
        "totp_tolerance",
        "verify_url",
        *_MFA_PATH_KEYS,
    }
)


def _mfa(value: object) -> MFASettings | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ImproperlyConfigured("CROSS_AUTH['MFA'] must be a dict")
    unknown = set(value) - _MFA_KEYS
    if unknown:
        raise ImproperlyConfigured(
            "Unsupported CROSS_AUTH['MFA'] key(s): "
            + ", ".join(sorted(map(str, unknown)))
        )
    if not settings.USE_TZ:
        # Core compares stored times with the current time in UTC.
        raise ImproperlyConfigured("CROSS_AUTH['MFA'] needs USE_TZ = True")
    return _mfa_settings(value)


def _mfa_settings(value: Mapping[Any, object]) -> MFASettings:
    functions: dict[str, Callable[..., Any]] = {}
    for key in _MFA_PATH_KEYS:
        path = value.get(key)
        if path is None:
            continue
        if not isinstance(path, str):
            raise ImproperlyConfigured(
                f"CROSS_AUTH['MFA']['{key}'] must be the dotted path of a function"
            )
        function = import_string(path)
        if not callable(function):
            raise ImproperlyConfigured(
                f"CROSS_AUTH['MFA']['{key}'] {path!r} is not callable"
            )
        functions[key] = function
    if ("encrypt" in functions) != ("decrypt" in functions):
        raise ImproperlyConfigured(
            "CROSS_AUTH['MFA'] needs both 'encrypt' and 'decrypt', or neither"
        )
    verify_url = value.get("verify_url")
    if verify_url is not None and (not isinstance(verify_url, str) or not verify_url):
        raise ImproperlyConfigured(
            "CROSS_AUTH['MFA']['verify_url'] must be a URL name or path"
        )
    config: dict[str, object] = {
        key: value[key]
        for key in value
        if key not in _MFA_PATH_KEYS and key != "verify_url"
    }
    config.setdefault("issuer", "")
    custom = "encrypt" in functions
    if custom:
        config["encrypt"] = functions["encrypt"]
        config["decrypt"] = functions["decrypt"]
    try:
        # Checked with stand-in keys: the real ones come from SECRET_KEY.
        resolve_config(
            cast(
                MFAConfig, {**config, **({} if custom else {"secret_keys": ["check"]})}
            )
        )
    except ValueError as error:
        raise ImproperlyConfigured(
            str(error).replace("config['mfa']", "CROSS_AUTH['MFA']")
        ) from error
    return MFASettings(
        config=cast(MFAConfig, config),
        requires_mfa=functions.get("requires_mfa"),
        custom_encryption=custom,
        verify_url=verify_url,
    )


@cache
def get_settings() -> CrossAuthSettings:
    raw: Mapping[str, Any] = getattr(settings, "CROSS_AUTH", {})
    unknown = set(raw) - _KNOWN_KEYS
    if unknown:
        raise ImproperlyConfigured(
            f"Unknown CROSS_AUTH setting(s): {', '.join(sorted(unknown))}"
        )

    factory: UserFactory = create_user
    factory_path = raw.get("CREATE_USER")
    if factory_path is not None:
        if not isinstance(factory_path, str):
            raise ImproperlyConfigured(
                "CROSS_AUTH['CREATE_USER'] must be the dotted path of a function"
            )
        factory = import_string(factory_path)
        if not callable(factory):
            raise ImproperlyConfigured(
                f"CROSS_AUTH['CREATE_USER'] {factory_path!r} is not callable"
            )

    base_url = raw.get("BASE_URL")
    if base_url is not None and not (
        isinstance(base_url, str) and base_url.startswith(("https://", "http://"))
    ):
        raise ImproperlyConfigured(
            "CROSS_AUTH['BASE_URL'] must be an origin such as https://example.com"
        )

    return CrossAuthSettings(
        providers=_providers(raw.get("PROVIDERS", [])),
        create_user=factory,
        password_login=_bool(raw, "PASSWORD_LOGIN", True),
        account_linking=_account_linking(raw.get("ACCOUNT_LINKING", {})),
        require_verified_email=_bool(raw, "REQUIRE_VERIFIED_EMAIL", True),
        base_url=base_url,
        session_activity_interval=_seconds(
            raw,
            "SESSION_ACTIVITY_INTERVAL",
            300,
            maximum=_MAX_SESSION_ACTIVITY_INTERVAL,
        ),
        session_store_ip=_bool(raw, "SESSION_STORE_IP", True),
        oauth_server=_oauth_server(raw.get("OAUTH_SERVER")),
        provider_tokens=_provider_tokens(raw.get("PROVIDER_TOKENS")),
        mfa=_mfa(raw.get("MFA")),
    )


def _reset(*, setting: str, **kwargs: object) -> None:
    if setting in {"CROSS_AUTH", "AUTH_USER_MODEL", "USE_TZ"}:
        get_settings.cache_clear()


setting_changed.connect(_reset)
