"""Core native id_token sign-in, exercised without FastAPI.

The FastAPI facade is covered by tests/fastapi/test_id_token_sign_in.py.
"""

import hashlib
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any, get_args

import pytest

from cross_auth import SecondaryStorage
from cross_auth._context import Context
from cross_auth._native import sign_in_with_id_token
from cross_auth.exceptions import CrossAuthException
from cross_auth.hooks._types import HookEventName
from cross_auth.social_providers.github import GitHubProvider
from cross_auth.social_providers.oauth import OAuth2Exception
from cross_auth.social_providers.oidc import OIDCProvider

VALID_TOKEN = "valid-id-token"


class StubOIDCProvider(OIDCProvider):
    id = "stub"

    def __init__(self, claims: dict[str, Any]):
        super().__init__(client_id="stub-client")
        self.claims = claims

    def validate_id_token(
        self, id_token: str, secondary_storage: SecondaryStorage
    ) -> dict[str, Any]:
        if id_token != VALID_TOKEN:
            raise OAuth2Exception(error="invalid_token", error_description="bad token")
        return dict(self.claims)


def _sign_in(context: Context, provider: OIDCProvider, **kwargs: Any):
    return sign_in_with_id_token(
        context=context,
        providers={provider.id: provider},
        provider=provider.id,
        id_token=VALID_TOKEN,
        **kwargs,
    )


def _trace_hooks(context: Context) -> list[str]:
    trace: list[str] = []
    for name in get_args(HookEventName):
        context.hooks.register_before(
            name, lambda event, name=name: trace.append(f"before:{name}")
        )
        context.hooks.register_after(
            name, lambda event, name=name: trace.append(f"after:{name}")
        )
    return trace


def test_creates_then_resolves_user_without_starting_a_session(
    context: Context, session_storage, accounts_storage
):
    provider = StubOIDCProvider(
        {"sub": "native-1", "email": " New@Example.COM ", "email_verified": True}
    )
    trace = _trace_hooks(context)

    user, account = _sign_in(context, provider)

    assert user.created is True
    assert account.created is True
    assert user.user.email == "new@example.com"
    assert account.account.user_id == user.user.id
    assert account.account.access_token is None
    assert account.account.refresh_token is None
    assert trace == [
        "before:oauth.id_token",
        "before:user.create",
        "before:social_account.create",
        "after:user.create",
        "after:social_account.create",
        "after:oauth.id_token",
    ]
    # Verification resolves an identity; it is not a login.
    assert session_storage.records == {}

    trace.clear()
    again, again_account = _sign_in(context, provider)

    assert again.created is False
    assert again_account.created is False
    assert again.user.id == user.user.id
    assert trace == [
        "before:oauth.id_token",
        "before:social_account.update",
        "after:social_account.update",
        "after:oauth.id_token",
    ]
    assert session_storage.records == {}


def test_connected_only_identity_cannot_sign_in(context: Context, accounts_storage):
    accounts_storage.create_social_account(
        user_id="test",
        provider="stub",
        provider_user_id="connected-1",
        access_token=None,
        refresh_token=None,
        access_token_expires_at=None,
        refresh_token_expires_at=None,
        scope=None,
        user_info={},
        provider_email="test@example.com",
        provider_email_verified=True,
        is_login_method=False,
    )
    provider = StubOIDCProvider(
        {"sub": "connected-1", "email": "test@example.com", "email_verified": True}
    )
    trace = _trace_hooks(context)

    with pytest.raises(CrossAuthException, match="^access_denied$"):
        _sign_in(context, provider)

    assert trace == ["before:oauth.id_token"]


def test_existing_email_requires_account_linking(context: Context):
    # The fixture pre-seeds test@example.com.
    provider = StubOIDCProvider(
        {"sub": "native-2", "email": "Test@Example.com", "email_verified": True}
    )

    with pytest.raises(CrossAuthException) as excinfo:
        _sign_in(context, provider)
    assert excinfo.value.error == "account_not_linked"

    context.config["account_linking"] = {"enabled": True}
    user, account = _sign_in(context, provider)

    assert user.created is False
    assert account.created is True
    assert user.user.email == "test@example.com"


def test_only_display_metadata_is_merged_into_verified_claims(context: Context):
    provider = StubOIDCProvider(
        {"sub": "attacker", "email": "attacker@example.com", "email_verified": False}
    )
    seen: list[dict[str, Any]] = []
    context.hooks.register_before(
        "user.create", lambda event: seen.append(dict(event.user_info))
    )

    user, _ = _sign_in(
        context,
        provider,
        user_info={
            "id": "victim",
            "email": "victim@example.com",
            "email_verified": True,
            "is_superuser": True,
            "name": "Display Name",
            "picture": "https://example.com/avatar.png",
        },
    )

    assert user.user.email == "attacker@example.com"
    assert seen == [
        {
            "id": "attacker",
            "email": "attacker@example.com",
            "email_verified": False,
            "name": "Display Name",
            "picture": "https://example.com/avatar.png",
        }
    ]


@pytest.mark.parametrize("hashed", [False, True])
def test_nonce_matches_raw_or_hashed_claim(context: Context, hashed: bool):
    nonce = "random-nonce-é"
    claim = hashlib.sha256(nonce.encode()).hexdigest() if hashed else nonce
    provider = StubOIDCProvider(
        {
            "sub": "nonce-user",
            "email": "nonce@example.com",
            "email_verified": True,
            "nonce": claim,
        }
    )

    user, _ = _sign_in(context, provider, nonce=nonce)

    assert user.created is True


def test_nonce_mismatch_is_rejected_before_resolution(
    context: Context, accounts_storage
):
    provider = StubOIDCProvider(
        {
            "sub": "nonce-user",
            "email": "nonce@example.com",
            "email_verified": True,
            "nonce": "other",
        }
    )
    trace = _trace_hooks(context)

    with pytest.raises(OAuth2Exception, match="nonce mismatch"):
        _sign_in(context, provider, nonce="expected")

    assert trace == ["before:oauth.id_token"]
    assert accounts_storage.find_user_by_email("nonce@example.com") is None


def test_rejects_unknown_and_non_oidc_providers(context: Context):
    github = GitHubProvider(client_id="x", client_secret="y")

    for name in ("missing", "github"):
        with pytest.raises(CrossAuthException) as excinfo:
            sign_in_with_id_token(
                context=context,
                providers={"github": github},
                provider=name,
                id_token=VALID_TOKEN,
            )
        assert excinfo.value.error == "invalid_request"


_IMPORT_ISOLATION_SCRIPT = textwrap.dedent(
    """
    import sys
    from importlib.abc import MetaPathFinder

    class BlockFrameworks(MetaPathFinder):
        def find_spec(self, name, path=None, target=None):
            if name.split(".")[0] in {"fastapi", "starlette"}:
                raise ImportError(f"blocked import: {name}")
            return None

    sys.meta_path.insert(0, BlockFrameworks())

    import cross_auth
    import cross_auth._auth_flow
    import cross_auth._context
    import cross_auth._issuer
    import cross_auth.hooks
    import cross_auth.storage.sqlmodel
    from cross_auth._native import sign_in_with_id_token
    from tests.conftest import MemoryAccountsStorage, MemoryStorage
    from tests.test_native import VALID_TOKEN, StubOIDCProvider

    context = cross_auth._context.Context(
        secondary_storage=MemoryStorage(),
        accounts_storage=MemoryAccountsStorage("unused-hash"),
        get_user_from_request=lambda request: None,
    )
    provider = StubOIDCProvider(
        {"sub": "isolated", "email": "isolated@example.com", "email_verified": True}
    )
    user, _ = sign_in_with_id_token(
        context=context,
        providers={provider.id: provider},
        provider=provider.id,
        id_token=VALID_TOKEN,
    )
    assert user.created
    assert not {"fastapi", "starlette"} & set(sys.modules)
    """
)


def test_core_sign_in_does_not_import_fastapi_or_starlette():
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, "-c", _IMPORT_ISOLATION_SCRIPT],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
