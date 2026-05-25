from __future__ import annotations

import uuid
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, cast
from urllib.parse import urlencode

from cross_web import HTTPRequest
from fastapi import Depends, FastAPI, Form, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext

from cross_auth import (
    AccountsStorage,
    SecondaryStorage,
    SessionConfig,
    SessionListOrder,
    SessionListResult,
    SessionStatus,
    SessionStorage,
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
MAX_HOOK_EVENTS = 20
# Small page size so the demo's handful of sessions paginate visibly.
SESSIONS_PAGE_SIZE = 5
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


@dataclass
class DemoSessionRecord:
    id: str
    token_hash: str
    user_id: str
    created_at: datetime
    updated_at: datetime
    expires_at: datetime
    last_active_at: datetime | None = None
    revoked_at: datetime | None = None
    client_id: str | None = None
    client_name: str | None = None
    user_agent: str | None = None
    ip: str | None = None

    @property
    def status(self) -> SessionStatus:
        return session_status(self, now=datetime.now(tz=UTC))


@dataclass
class DemoSessionListResult:
    records: list[DemoSessionRecord]
    next_cursor: str | None = None


class MemorySessionStorage(SessionStorage):
    def __init__(self) -> None:
        self.sessions_by_id: dict[str, DemoSessionRecord] = {}

    def create(
        self,
        *,
        token_hash: str,
        user_id: Any,
        created_at: datetime,
        updated_at: datetime,
        expires_at: datetime,
        client_id: str | None = None,
        client_name: str | None = None,
        user_agent: str | None = None,
        ip: str | None = None,
        last_active_at: datetime | None = None,
    ) -> DemoSessionRecord:
        record = DemoSessionRecord(
            id=str(uuid.uuid4()),
            token_hash=token_hash,
            user_id=str(user_id),
            created_at=created_at,
            updated_at=updated_at,
            expires_at=expires_at,
            client_id=client_id,
            client_name=client_name,
            user_agent=user_agent,
            ip=ip,
            last_active_at=last_active_at,
        )
        self.sessions_by_id[record.id] = record
        return record

    def get(self, *, token_hash: str, now: datetime) -> DemoSessionRecord | None:
        record = next(
            (
                record
                for record in self.sessions_by_id.values()
                if record.token_hash == token_hash
            ),
            None,
        )
        if record is None:
            return None
        if record.revoked_at is not None or now > record.expires_at:
            return None
        return record

    def get_any(self, session_id: Any) -> DemoSessionRecord | None:
        return self.sessions_by_id.get(str(session_id))

    def list_for_user(
        self,
        user_id: Any,
        *,
        now: datetime,
        status: SessionStatus | None = None,
        order_by: SessionListOrder = "updated_at_desc",
        limit: int = 50,
        cursor: str | None = None,
    ) -> SessionListResult:
        records = [
            record
            for record in self.sessions_by_id.values()
            if record.user_id == str(user_id)
        ]
        if status is not None:
            records = [
                record
                for record in records
                if session_status(record, now=now) == status
            ]

        field, direction = order_by.rsplit("_", 1)
        # Tie-break on id so the order is total and the cursor is stable.
        records.sort(
            key=lambda record: (getattr(record, field), record.id),
            reverse=direction == "desc",
        )

        # The cursor is the id of the last record from the previous page. A real
        # store would encode the (sort key, id) pair so it can resume with an
        # indexed range query instead of scanning; for the demo we slice.
        if cursor is not None:
            ids = [record.id for record in records]
            if cursor in ids:
                records = records[ids.index(cursor) + 1 :]

        page = records[:limit]
        has_more = len(records) > limit
        next_cursor = page[-1].id if has_more and page else None
        return cast(
            SessionListResult,
            DemoSessionListResult(records=page, next_cursor=next_cursor),
        )

    def refresh(
        self,
        session_id: Any,
        *,
        updated_at: datetime,
        expires_at: datetime,
        last_active_at: datetime | None = None,
    ) -> DemoSessionRecord | None:
        record = self.get_any(session_id)
        if record is None:
            return None
        record.updated_at = updated_at
        record.expires_at = expires_at
        record.last_active_at = last_active_at
        return record

    def revoke(self, session_id: Any, *, revoked_at: datetime) -> None:
        record = self.get_any(session_id)
        if record is not None:
            record.revoked_at = revoked_at

    def revoke_all_for_user(
        self,
        user_id: Any,
        *,
        revoked_at: datetime,
        except_session_id: Any | None = None,
    ) -> int:
        count = 0
        for record in self.sessions_by_id.values():
            if record.user_id != str(user_id):
                continue
            if except_session_id is not None and record.id == str(except_session_id):
                continue
            if record.revoked_at is None:
                record.revoked_at = revoked_at
                count += 1
        return count


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


def session_status(record: DemoSessionRecord, *, now: datetime) -> SessionStatus:
    if record.revoked_at is not None:
        return "revoked"
    if now > record.expires_at:
        return "expired"
    return "active"


def session_access_label(record: DemoSessionRecord) -> str:
    if record.client_id:
        return f"Authorized Application ({record.client_name or record.client_id})"
    if record.user_agent:
        if "Chrome" in record.user_agent:
            browser = "Chrome"
        elif "Firefox" in record.user_agent:
            browser = "Firefox"
        elif "Safari" in record.user_agent:
            browser = "Safari"
        else:
            browser = "Browser"
        return f"Browser ({browser})"
    return "Browser"


def serialize_session(
    record: DemoSessionRecord,
    *,
    current_session_id: str | None,
) -> dict[str, Any]:
    return {
        "id": record.id,
        "user_id": record.user_id,
        "status": record.status,
        "access_label": session_access_label(record),
        "created_at": record.created_at.isoformat(),
        "updated_at": record.updated_at.isoformat(),
        "expires_at": record.expires_at.isoformat(),
        "last_active_at": (
            record.last_active_at.isoformat() if record.last_active_at else None
        ),
        "revoked_at": record.revoked_at.isoformat() if record.revoked_at else None,
        "client_id": record.client_id,
        "client_name": record.client_name,
        "user_agent": record.user_agent,
        "ip": record.ip,
        "current": record.id == current_session_id,
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


def resolve_auth_user(request: HTTPRequest) -> DemoUser | None:
    session_user = get_session_user(
        request,
        session_storage,
        accounts_storage,
        SESSION_CONFIG,
    )
    if session_user is not None:
        return cast(DemoUser, session_user)

    return None


github = GitHubProvider(
    client_id="demo-client",
    client_secret="demo-secret",
    authorization_endpoint=f"{GITHUB_MOCK_BASE_URL}/login/oauth/authorize",
    token_endpoint=f"{GITHUB_MOCK_BASE_URL}/login/oauth/access_token",
    api_base_url=f"{GITHUB_MOCK_BASE_URL}/api",
)

secondary_storage = MemorySecondaryStorage()
session_storage = MemorySessionStorage()
accounts_storage = MemoryAccountsStorage()
SESSION_CONFIG: SessionConfig = {
    "update_age": 60,
    "cookies": {
        "auth": True,
        "name": SESSION_COOKIE_NAME,
        "secure": False,
    },
}

auth = CrossAuth(
    providers=[github],
    storage=secondary_storage,
    accounts_storage=accounts_storage,
    session_storage=session_storage,
    trusted_origins=[*SPA_TRUSTED_REDIRECT_HOSTS, *BACKEND_TRUSTED_REDIRECT_HOSTS],
    get_user_from_request=resolve_auth_user,
    default_next_url="/profile",
    config={
        "account_linking": {"enabled": True},
        "allowed_client_ids": [SPA_CLIENT_ID],
        "session": SESSION_CONFIG,
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
    record_hook_event(
        "after:logout",
        session_id="" if event.session_record is None else str(event.session_record.id),
    )


@auth.before("oauth.callback")
def require_verified_provider_email(event: BeforeOAuthCallbackEvent) -> None:
    if event.validated_user_info.email_verified is not True:
        raise CrossAuthException(
            "email_not_verified",
            "The provider email must be verified for this demo.",
        )


@auth.after("oauth.callback")
def audit_oauth_callback(event: AfterOAuthCallbackEvent) -> None:
    record_hook_event(
        "after:oauth.callback",
        flow=event.auth_request.flow,
        provider=event.provider.id,
        user_id=str(event.user.id),
        created_user="yes" if event.created_user is not None else "no",
    )


@auth.after("token.authorization_code")
def audit_token_exchange(event: AfterTokenAuthorizationCodeEvent) -> None:
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
    request: Request,
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
) -> RedirectResponse:
    user = auth.authenticate(email, password)
    if user is None:
        return RedirectResponse(url="/?error=invalid_credentials", status_code=303)

    response = RedirectResponse(url="/profile", status_code=303)
    auth.login(
        str(user.id),
        response=response,
        metadata={"user_agent": request.headers.get("User-Agent")},
    )
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


@app.get("/sessions")
def sessions_page(
    request: Request,
    response: Response,
    user: Annotated[UserProtocol | None, Depends(auth.get_current_user)],
    status: SessionStatus | None = None,
    cursor: str | None = None,
):
    if user is None:
        return RedirectResponse(url="/", status_code=303)

    current_session = auth.get_current_session(request, response)
    result = auth.list_sessions(
        str(user.id),
        status=status,
        limit=SESSIONS_PAGE_SIZE,
        cursor=cursor,
    )
    sessions = [
        serialize_session(
            cast(DemoSessionRecord, record),
            current_session_id=(
                str(current_session.id) if current_session is not None else None
            ),
        )
        for record in result.records
    ]

    next_query = None
    if result.next_cursor is not None:
        params = {"cursor": result.next_cursor}
        if status is not None:
            params["status"] = status
        next_query = urlencode(params)

    return templates.TemplateResponse(
        request,
        "sessions.html",
        {
            "current_status": status,
            "hook_events": hook_events[:5],
            "sessions": sessions,
            "user": user,
            "next_query": next_query,
        },
    )


@app.post("/sessions/{session_id}/revoke")
def revoke_session_form(
    session_id: str,
    user: Annotated[UserProtocol, Depends(auth.require_current_user)],
) -> RedirectResponse:
    auth.revoke_session(session_id, user_id=str(user.id))
    return RedirectResponse(url="/sessions", status_code=303)


@app.post("/sessions/revoke-other")
def revoke_other_sessions_form(
    request: Request,
    user: Annotated[UserProtocol, Depends(auth.require_current_user)],
    response: Response,
) -> RedirectResponse:
    current_session = auth.get_current_session(request, response)
    if current_session is not None:
        auth.revoke_other_sessions(
            user_id=str(user.id),
            keep_session_id=current_session.id,
        )
    return RedirectResponse(url="/sessions", status_code=303)


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


@app.get("/api/sessions")
def api_sessions(
    request: Request,
    response: Response,
    user: Annotated[UserProtocol, Depends(auth.require_current_user)],
    status: SessionStatus | None = None,
    cursor: str | None = None,
) -> JSONResponse:
    current_session = auth.get_current_session(request, response)
    result = auth.list_sessions(
        str(user.id),
        status=status,
        limit=SESSIONS_PAGE_SIZE,
        cursor=cursor,
    )
    return JSONResponse(
        {
            "sessions": [
                serialize_session(
                    cast(DemoSessionRecord, record),
                    current_session_id=(
                        str(current_session.id) if current_session is not None else None
                    ),
                )
                for record in result.records
            ],
            "next_cursor": result.next_cursor,
        }
    )


@app.post("/api/sessions/{session_id}/revoke")
def api_revoke_session(
    session_id: str,
    user: Annotated[UserProtocol, Depends(auth.require_current_user)],
) -> JSONResponse:
    auth.revoke_session(session_id, user_id=str(user.id))
    return JSONResponse({"ok": True})


@app.post("/api/sessions/revoke-other")
def api_revoke_other_sessions(
    request: Request,
    user: Annotated[UserProtocol, Depends(auth.require_current_user)],
    response: Response,
) -> JSONResponse:
    current_session = auth.get_current_session(request, response)
    revoked = 0
    if current_session is not None:
        revoked = auth.revoke_other_sessions(
            user_id=str(user.id),
            keep_session_id=current_session.id,
        )
    return JSONResponse({"ok": True, "revoked": revoked})
