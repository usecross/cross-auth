from __future__ import annotations

import uuid
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, cast

import jwt
from cross_web import AsyncHTTPRequest
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext

from cross_auth import (
    AccountsStorage,
    SecondaryStorage,
    SessionConfig,
)
from cross_auth import User as UserProtocol
from cross_auth._session import get_current_user as get_session_user
from cross_auth.exceptions import CrossAuthException
from cross_auth.fastapi import CrossAuth
from cross_auth.hooks import (
    AfterAuthenticateEvent,
    AfterLoginEvent,
    AfterLogoutEvent,
    AfterOAuthCallbackEvent,
    AfterTokenAuthorizationCodeEvent,
    BeforeAuthenticateEvent,
    BeforeOAuthCallbackEvent,
)
from cross_auth.social_providers.github import GitHubProvider

APP_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(APP_DIR / "templates"))

SESSION_COOKIE_NAME = "cross_auth_example_session"
DEMO_EMAIL = "demo@example.com"
DEMO_PASSWORD = "password123"  # noqa: S105
GITHUB_MOCK_BASE_URL = "https://github-oauth-mock.fastapicloud.dev"
SPA_DEMO_URL = "http://localhost:5173"
SPA_CLIENT_ID = "spa-example"
BACKEND_TRUSTED_REDIRECT_HOSTS = [
    "localhost:8000",
    "127.0.0.1:8000",
]
TOKEN_ISSUER = "cross-auth-fastapi-example"
TOKEN_SECRET = "cross-auth-fastapi-example-secret"  # noqa: S105
TOKEN_EXPIRES_IN = 3600
MAX_HOOK_EVENTS = 20
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SPA_CORS_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]
SPA_TRUSTED_REDIRECT_HOSTS = [
    "localhost:5173",
    "127.0.0.1:5173",
]


def same_id(left: Any, right: Any) -> bool:
    return str(left) == str(right)


@dataclass
class DemoSocialAccount:
    id: str
    user_id: str
    provider_user_id: str
    provider: str
    provider_email: str | None
    provider_email_verified: bool | None
    is_login_method: bool
    access_token: str | None = None
    refresh_token: str | None = None
    access_token_expires_at: datetime | None = None
    refresh_token_expires_at: datetime | None = None
    scope: str | None = None
    user_info: dict[str, Any] = field(default_factory=dict)


@dataclass
class DemoUser:
    id: str
    email: str
    email_verified: bool
    hashed_password: str | None = None
    social_accounts: list[DemoSocialAccount] = field(default_factory=list)

    @property
    def has_usable_password(self) -> bool:
        return self.hashed_password is not None


class MemorySecondaryStorage(SecondaryStorage):
    def __init__(self) -> None:
        self.data: dict[str, str] = {}

    def set(self, key: str, value: str, ttl: int | None = None) -> None:
        del ttl
        self.data[key] = value

    def get(self, key: str) -> str | None:
        return self.data.get(key)

    def delete(self, key: str) -> None:
        self.data.pop(key, None)

    def pop(self, key: str) -> str | None:
        return self.data.pop(key, None)


class MemoryAccountsStorage(AccountsStorage):
    def __init__(self) -> None:
        self.users_by_id: dict[str, DemoUser] = {}
        self._seed_demo_user()

    def _seed_demo_user(self) -> None:
        user = DemoUser(
            id="demo-user",
            email=DEMO_EMAIL,
            email_verified=True,
            hashed_password=pwd_context.hash(DEMO_PASSWORD),
        )
        self.users_by_id[user.id] = user

    def find_user_by_email(self, email: str) -> DemoUser | None:
        normalized = email.lower()
        return next(
            (
                user
                for user in self.users_by_id.values()
                if user.email.lower() == normalized
            ),
            None,
        )

    def find_user_by_id(self, id: Any) -> DemoUser | None:
        return self.users_by_id.get(str(id))

    def find_social_account(
        self,
        *,
        provider: str,
        provider_user_id: str,
    ) -> DemoSocialAccount | None:
        for user in self.users_by_id.values():
            for account in user.social_accounts:
                if (
                    account.provider == provider
                    and account.provider_user_id == provider_user_id
                ):
                    return account
        return None

    def find_social_account_by_id(
        self,
        social_account_id: Any,
    ) -> DemoSocialAccount | None:
        return next(
            (
                account
                for user in self.users_by_id.values()
                for account in user.social_accounts
                if same_id(account.id, social_account_id)
            ),
            None,
        )

    def list_social_accounts(self, *, user_id: Any) -> list[DemoSocialAccount]:
        user = self.find_user_by_id(user_id)
        if user is None:
            return []
        return list(user.social_accounts)

    def create_user(
        self,
        *,
        user_info: dict[str, Any],
        email: str,
        email_verified: bool,
    ) -> DemoUser:
        user = DemoUser(
            id=str(uuid.uuid4()),
            email=email,
            email_verified=email_verified,
        )
        self.users_by_id[user.id] = user
        return user

    def create_social_account(
        self,
        *,
        user_id: Any,
        provider: str,
        provider_user_id: str,
        access_token: str | None,
        refresh_token: str | None,
        access_token_expires_at,
        refresh_token_expires_at,
        scope: str | None,
        user_info: dict[str, Any],
        provider_email: str | None,
        provider_email_verified: bool | None,
        is_login_method: bool,
    ) -> DemoSocialAccount:
        user = self.find_user_by_id(user_id)
        if user is None:
            raise ValueError("User does not exist")

        social_account = DemoSocialAccount(
            id=str(uuid.uuid4()),
            user_id=str(user.id),
            provider=provider,
            provider_user_id=provider_user_id,
            access_token=access_token,
            refresh_token=refresh_token,
            access_token_expires_at=access_token_expires_at,
            refresh_token_expires_at=refresh_token_expires_at,
            scope=scope,
            user_info=user_info,
            provider_email=provider_email,
            provider_email_verified=provider_email_verified,
            is_login_method=is_login_method,
        )
        user.social_accounts.append(social_account)
        return social_account

    def update_social_account(
        self,
        social_account_id: Any,
        *,
        access_token: str | None,
        refresh_token: str | None,
        access_token_expires_at,
        refresh_token_expires_at,
        scope: str | None,
        user_info: dict[str, Any],
        provider_email: str | None,
        provider_email_verified: bool | None,
    ) -> DemoSocialAccount:
        social_account = next(
            (
                account
                for user in self.users_by_id.values()
                for account in user.social_accounts
                if same_id(account.id, social_account_id)
            ),
            None,
        )
        if social_account is None:
            raise ValueError("Social account does not exist")

        social_account.access_token = access_token
        social_account.refresh_token = refresh_token
        social_account.access_token_expires_at = access_token_expires_at
        social_account.refresh_token_expires_at = refresh_token_expires_at
        social_account.scope = scope
        social_account.user_info = user_info
        social_account.provider_email = provider_email
        social_account.provider_email_verified = provider_email_verified
        return social_account

    def delete_social_account(self, social_account_id: Any) -> None:
        for user in self.users_by_id.values():
            user.social_accounts = [
                account
                for account in user.social_accounts
                if not same_id(account.id, social_account_id)
            ]


def serialize_user(user: DemoUser) -> dict[str, Any]:
    return {
        "id": user.id,
        "email": user.email,
        "email_verified": user.email_verified,
        "social_accounts": [
            {
                "id": account.id,
                "provider": account.provider,
                "provider_user_id": account.provider_user_id,
                "provider_email": account.provider_email,
                "provider_email_verified": account.provider_email_verified,
                "is_login_method": account.is_login_method,
            }
            for account in user.social_accounts
        ],
    }


def get_error_message(error: str | None) -> str | None:
    if error == "invalid_credentials":
        return "The demo credentials were invalid."
    if error == "access_denied":
        return "GitHub login was cancelled."
    if error == "invalid_state":
        return "The GitHub login session expired. Please try again."
    if error == "oauth_failed":
        return "GitHub login failed. Please try again."
    if error == "account_not_linked":
        return "A local account with that email already exists but could not be linked automatically."
    if error == "email_not_verified":
        return "The provider reported an unverified email address."
    return None


def create_demo_token(user_id: str) -> tuple[str, int]:
    now = datetime.now(tz=UTC)
    payload = {
        "sub": user_id,
        "iss": TOKEN_ISSUER,
        "iat": now,
        "exp": now + timedelta(seconds=TOKEN_EXPIRES_IN),
    }
    return jwt.encode(payload, TOKEN_SECRET, algorithm="HS256"), TOKEN_EXPIRES_IN


hook_events: list[dict[str, str]] = []


def record_hook_event(name: str, **fields: str) -> None:
    hook_events.insert(
        0,
        {
            "time": datetime.now(tz=UTC).strftime("%H:%M:%S"),
            "name": name,
            **fields,
        },
    )
    del hook_events[MAX_HOOK_EVENTS:]


def resolve_bearer_token(token: str) -> DemoUser:
    try:
        payload = jwt.decode(
            token,
            TOKEN_SECRET,
            algorithms=["HS256"],
            issuer=TOKEN_ISSUER,
        )
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=401, detail="Invalid bearer token") from e

    user_id = payload.get("sub")
    if not isinstance(user_id, str):
        raise HTTPException(status_code=401, detail="Invalid bearer token")

    user = accounts_storage.find_user_by_id(user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")

    return user


def resolve_bearer_user(request: Request) -> DemoUser:
    authorization = request.headers.get("Authorization")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")

    token = authorization.split(" ", 1)[1]
    return resolve_bearer_token(token)


def resolve_auth_user(request: AsyncHTTPRequest) -> DemoUser | None:
    authorization = request.headers.get("Authorization")
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1]
        try:
            return resolve_bearer_token(token)
        except HTTPException:
            return None

    return cast(
        DemoUser | None,
        get_session_user(
            request,
            secondary_storage,
            accounts_storage,
            {"cookie_name": SESSION_COOKIE_NAME, "secure": False},
        ),
    )


github = GitHubProvider(
    client_id="demo-client",
    client_secret="demo-secret",
    authorization_endpoint=f"{GITHUB_MOCK_BASE_URL}/login/oauth/authorize",
    token_endpoint=f"{GITHUB_MOCK_BASE_URL}/login/oauth/access_token",
    api_base_url=f"{GITHUB_MOCK_BASE_URL}/api",
)

secondary_storage = MemorySecondaryStorage()
accounts_storage = MemoryAccountsStorage()
SESSION_CONFIG: SessionConfig = {
    "cookie_name": SESSION_COOKIE_NAME,
    "secure": False,
}

auth = CrossAuth(
    providers=[github],
    storage=secondary_storage,
    accounts_storage=accounts_storage,
    create_token=create_demo_token,
    trusted_origins=[*SPA_TRUSTED_REDIRECT_HOSTS, *BACKEND_TRUSTED_REDIRECT_HOSTS],
    session_config=SESSION_CONFIG,
    get_user_from_request=resolve_auth_user,
    default_next_url="/profile",
    config={
        "account_linking": {"enabled": True},
        "allowed_client_ids": [SPA_CLIENT_ID],
    },
)


@auth.before("authenticate")
def normalize_password_login(event: BeforeAuthenticateEvent) -> BeforeAuthenticateEvent:
    return replace(event, email=event.email.strip().lower())


@auth.after("authenticate")
def audit_password_login(event: AfterAuthenticateEvent) -> None:
    record_hook_event(
        "after:authenticate",
        email=event.email,
        user_id="" if event.user is None else str(event.user.id),
        result="success" if event.user is not None else "failed",
    )


@auth.after("login")
def audit_session_login(event: AfterLoginEvent) -> None:
    event.response.headers = {
        **(event.response.headers or {}),
        "X-Cross-Auth-Hook": "login",
    }
    record_hook_event("after:login", user_id=event.user_id)


@auth.after("logout")
def audit_session_logout(event: AfterLogoutEvent) -> None:
    record_hook_event("after:logout", session_id=event.session_id or "")


@auth.before("oauth.callback")
async def require_verified_provider_email(event: BeforeOAuthCallbackEvent) -> None:
    if event.validated_user_info.email_verified is not True:
        raise CrossAuthException(
            "email_not_verified",
            "The provider email must be verified for this demo.",
        )


@auth.after("oauth.callback")
async def audit_oauth_callback(event: AfterOAuthCallbackEvent) -> None:
    record_hook_event(
        "after:oauth.callback",
        flow=event.auth_request.flow,
        provider=event.provider.id,
        user_id=str(event.user.id),
        created_user="yes" if event.created_user is not None else "no",
    )


@auth.after("token.authorization_code")
async def audit_token_exchange(event: AfterTokenAuthorizationCodeEvent) -> None:
    record_hook_event(
        "after:token.authorization_code",
        client_id=event.authorization_data.client_id,
        user_id=event.authorization_data.user_id,
    )


app = FastAPI(title="Cross-Auth FastAPI Hybrid Example")
app.add_middleware(
    CORSMiddleware,
    allow_origins=SPA_CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)
app.include_router(auth.router, prefix="/auth")


@app.get("/")
def home(
    request: Request,
    user: Annotated[UserProtocol | None, Depends(auth.get_current_user)],
    error: str | None = None,
):
    return templates.TemplateResponse(
        request,
        "home.html",
        {
            "demo_email": DEMO_EMAIL,
            "demo_password": DEMO_PASSWORD,
            "error_message": get_error_message(error),
            "github_login_url": "/auth/github/login?next=/profile",
            "github_mock_base_url": GITHUB_MOCK_BASE_URL,
            "hook_events": hook_events[:5],
            "spa_client_id": SPA_CLIENT_ID,
            "spa_demo_url": SPA_DEMO_URL,
            "user": user,
        },
    )


@app.post("/login")
def login(
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
) -> RedirectResponse:
    user = auth.authenticate(email, password)
    if user is None:
        return RedirectResponse(url="/?error=invalid_credentials", status_code=303)

    response = RedirectResponse(url="/profile", status_code=303)
    auth.login(str(user.id), response=response)
    return response


@app.post("/logout")
def logout(request: Request) -> RedirectResponse:
    response = RedirectResponse(url="/", status_code=303)
    auth.logout(request, response=response)
    return response


@app.get("/profile")
def profile(
    request: Request,
    user: Annotated[UserProtocol | None, Depends(auth.get_current_user)],
):
    if user is None:
        return RedirectResponse(url="/", status_code=303)

    return templates.TemplateResponse(
        request,
        "profile.html",
        {"hook_events": hook_events[:5], "user": user, "spa_client_id": SPA_CLIENT_ID},
    )


@app.get("/hooks")
def hooks_page(request: Request):
    return templates.TemplateResponse(
        request,
        "hooks.html",
        {"hook_events": hook_events},
    )


@app.get("/link-callback")
def link_callback(request: Request):
    return templates.TemplateResponse(
        request,
        "link_callback.html",
        {"next_url": "/profile"},
    )


@app.get("/api/me")
def api_me_session(
    user: Annotated[UserProtocol, Depends(auth.require_current_user)],
) -> JSONResponse:
    return JSONResponse(serialize_user(cast(DemoUser, user)))
