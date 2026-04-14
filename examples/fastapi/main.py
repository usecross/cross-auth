from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any, cast

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext

from cross_auth import AccountsStorage, SecondaryStorage, User as UserProtocol
from cross_auth.fastapi import CrossAuth

APP_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(APP_DIR / "templates"))

SESSION_COOKIE_NAME = "cross_auth_example_session"
DEMO_EMAIL = "demo@example.com"
DEMO_PASSWORD = "password123"  # noqa: S105
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


@dataclass
class DemoSocialAccount:
    id: str
    user_id: str
    provider_user_id: str
    provider: str
    provider_email: str | None
    provider_email_verified: bool | None
    is_login_method: bool


@dataclass
class DemoUser:
    id: str
    email: str
    email_verified: bool
    hashed_password: str | None = None
    social_accounts: list[DemoSocialAccount] = field(default_factory=list)


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
        del provider, provider_user_id
        return None

    def create_user(
        self,
        *,
        user_info: dict[str, Any],
        email: str,
        email_verified: bool,
    ) -> DemoUser:
        del user_info
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
        del (
            user_id,
            provider,
            provider_user_id,
            access_token,
            refresh_token,
            access_token_expires_at,
            refresh_token_expires_at,
            scope,
            user_info,
            provider_email,
            provider_email_verified,
            is_login_method,
        )
        raise NotImplementedError("Social accounts are not used in this example.")

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
        del (
            social_account_id,
            access_token,
            refresh_token,
            access_token_expires_at,
            refresh_token_expires_at,
            scope,
            user_info,
            provider_email,
            provider_email_verified,
        )
        raise NotImplementedError("Social accounts are not used in this example.")


def serialize_user(user: DemoUser) -> dict[str, Any]:
    return {
        "id": user.id,
        "email": user.email,
        "email_verified": user.email_verified,
        "social_accounts": [],
    }


def get_error_message(error: str | None) -> str | None:
    if error == "invalid_credentials":
        return "The demo credentials were invalid."
    return None


secondary_storage = MemorySecondaryStorage()
accounts_storage = MemoryAccountsStorage()
auth = CrossAuth(
    providers=[],
    storage=secondary_storage,
    accounts_storage=accounts_storage,
    create_token=lambda user_id: (f"unused-{user_id}", 0),
    trusted_origins=[],
    session_config={"cookie_name": SESSION_COOKIE_NAME, "secure": False},
)

app = FastAPI(title="Cross-Auth FastAPI Session Example")


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

    return templates.TemplateResponse(request, "profile.html", {"user": user})


@app.get("/api/me")
def api_me(
    user: Annotated[UserProtocol, Depends(auth.require_current_user)],
) -> JSONResponse:
    return JSONResponse(serialize_user(cast(DemoUser, user)))
