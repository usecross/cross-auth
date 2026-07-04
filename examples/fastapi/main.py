import threading
import time
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, cast
from urllib.parse import urlencode

import cross_auth
from cross_web import HTTPRequest
from fastapi import Depends, FastAPI, Form, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext
from sqlalchemy.pool import StaticPool
from sqlmodel import Field, Relationship, Session, SQLModel, create_engine

from cross_auth import (
    SecondaryStorage,
    SessionConfig,
    SessionStatus,
    session_status,
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
from cross_auth.storage.sqlmodel import (
    SQLModelAccountsStorage,
    SQLModelSessionStorage,
)

APP_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(APP_DIR / "templates"))

SESSION_COOKIE_NAME = "cross_auth_example_session"
DEMO_EMAIL = "demo@example.com"
DEMO_PASSWORD = "password123"  # noqa: S105
# A second password account whose social connections stay isolated from the
# shared demo user, so the disconnect e2e can delete a social account without
# racing the tests that link GitHub to demo@example.com.
CONNECT_DEMO_EMAIL = "connect-demo@example.com"
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


class MemorySecondaryStorage(SecondaryStorage):
    def __init__(self) -> None:
        self.data: dict[str, tuple[str, float | None]] = {}

    def set(self, key: str, value: str, ttl: int | None = None) -> None:
        expires_at = time.monotonic() + ttl if ttl is not None else None
        self.data[key] = (value, expires_at)

    def get(self, key: str) -> str | None:
        if (entry := self.data.get(key)) is None:
            return None
        value, expires_at = entry
        if expires_at is not None and time.monotonic() >= expires_at:
            del self.data[key]
            return None
        return value

    def delete(self, key: str) -> None:
        self.data.pop(key, None)

    def pop(self, key: str) -> str | None:
        value = self.get(key)
        self.data.pop(key, None)
        return value


# SQLModel table models satisfying the storage adapter protocols. The adapters
# validate these fields at construction (see _required_models), so a missing
# column fails at startup rather than mid-request.
class SocialAccount(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    provider: str
    provider_user_id: str
    access_token: str | None = None
    refresh_token: str | None = None
    access_token_expires_at: datetime | None = None
    refresh_token_expires_at: datetime | None = None
    scope: str | None = None
    provider_email: str | None = None
    provider_email_verified: bool | None = None
    is_login_method: bool = True

    user: "User" = Relationship(back_populates="social_accounts")


class WelcomeNote(SQLModel, table=True):
    # AccountsStore.on_signup adds one of these so the demo has a related row
    # that joins the same commit as the new user.
    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    message: str


class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    email: str = Field(index=True)
    email_verified: bool = False
    hashed_password: str | None = None
    # Extra demo column populated by AccountsStore.build_user.
    display_name: str | None = None

    social_accounts: list[SocialAccount] = Relationship(back_populates="user")

    @property
    def has_usable_password(self) -> bool:
        return self.hashed_password is not None


class SessionRecord(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    token_hash: str = Field(index=True)
    user_id: str = Field(index=True)
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
        return session_status(self)


# In-memory SQLite. StaticPool keeps a single shared connection (a fresh
# connection would open an empty database); check_same_thread lets FastAPI's
# threadpooled sync endpoints reach it. Restarting the process drops every
# table, so the demo keeps its "restart resets everything" property.
engine = create_engine(
    "sqlite://",
    poolclass=StaticPool,
    connect_args={"check_same_thread": False},
)
SQLModel.metadata.create_all(engine)

# StaticPool shares one SQLite connection, which SQLite can't use from two
# threads at once. FastAPI runs sync endpoints in a threadpool, so serialize the
# brief span each session holds the connection — mirroring the GIL-serialized
# dict access the demo's in-memory storage relied on before.
_db_lock = threading.Lock()


class _LockedSession(Session):
    def __enter__(self) -> Session:
        _db_lock.acquire()
        return super().__enter__()

    def __exit__(self, type_: Any, value: Any, traceback: Any) -> None:
        try:
            super().__exit__(type_, value, traceback)
        finally:
            _db_lock.release()


def open_db_session() -> Session:
    return _LockedSession(engine)


class AccountsStore(SQLModelAccountsStorage[User, SocialAccount]):
    UserModel = User
    SocialAccountModel = SocialAccount

    def build_user(
        self,
        *,
        session: Session,
        user_info: dict[str, object],
        email: str,
        email_verified: bool,
    ) -> User:
        # Guarantee: the only place the User row is constructed on OAuth signup.
        name = user_info.get("name")
        display_name = str(name) if name else email.split("@", 1)[0]
        return User(
            email=email,
            email_verified=email_verified,
            display_name=display_name,
        )

    def on_signup(
        self,
        *,
        session: Session,
        user: User,
        user_info: dict[str, object],
        email_verified: bool,
    ) -> None:
        # Guarantee: runs inside the signup transaction — raising rolls it back
        # and nothing is persisted. Uses a different domain than the
        # before("oauth.callback") hook (which runs first and would shadow it).
        if user.email.endswith("@banned.example"):
            raise CrossAuthException(
                "signup_blocked",
                "Signups from that domain are not allowed.",
            )
        # Guarantee: this row is committed in the same transaction as the user.
        session.flush()  # assign user.id before using it as a foreign key
        assert user.id is not None
        session.add(
            WelcomeNote(user_id=user.id, message=f"Welcome, {user.display_name}!")
        )

    def after_signup(
        self,
        *,
        user: User,
        user_info: dict[str, object],
    ) -> None:
        # Guarantee: runs after commit — the user is already persisted.
        record_hook_event("after_signup", user_id=str(user.id), email=user.email)


def serialize_user(user: User) -> dict[str, Any]:
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


def session_access_label(record: SessionRecord) -> str:
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
    record: SessionRecord,
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
        # Int PK vs. the string id resolved from the cookie — compare as strings.
        "current": str(record.id) == current_session_id,
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
    if error == "blocked_domain":
        return "That email domain is not allowed for this demo."
    if error == "signup_blocked":
        return "Signups from that email domain are not allowed."
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


def resolve_auth_user(request: HTTPRequest) -> User | None:
    session_user = get_session_user(
        request,
        session_storage,
        accounts_storage,
        SESSION_CONFIG,
    )
    if session_user is not None:
        return cast(User, session_user)

    return None


github = GitHubProvider(
    client_id="demo-client",
    client_secret="demo-secret",
    authorization_endpoint=f"{GITHUB_MOCK_BASE_URL}/login/oauth/authorize",
    token_endpoint=f"{GITHUB_MOCK_BASE_URL}/login/oauth/access_token",
    api_base_url=f"{GITHUB_MOCK_BASE_URL}/api",
)

secondary_storage = MemorySecondaryStorage()
# Swap for Redis: from cross_auth.storage.redis import RedisStorage
# storage = RedisStorage(redis.Redis.from_url(os.environ["REDIS_URL"]))
accounts_storage = AccountsStore(session_factory=open_db_session)
session_storage = SQLModelSessionStorage(SessionRecord, session_factory=open_db_session)


def seed_demo_user() -> None:
    # The password form's demo accounts. In-memory SQLite starts empty on every
    # run, so this reseeds the durable password users at each startup.
    with open_db_session() as session:
        session.add(
            User(
                email=DEMO_EMAIL,
                email_verified=True,
                hashed_password=pwd_context.hash(DEMO_PASSWORD),
                display_name="Demo User",
            )
        )
        session.add(
            User(
                email=CONNECT_DEMO_EMAIL,
                email_verified=True,
                hashed_password=pwd_context.hash(DEMO_PASSWORD),
                display_name="Connect Demo User",
            )
        )
        session.commit()


seed_demo_user()

SESSION_CONFIG: SessionConfig = {
    "update_age": 60,
    "cookies": {
        "auth": True,
        "name": SESSION_COOKIE_NAME,
        "secure": False,
    },
}


def normalize_login_email(email: str) -> str:
    # Core runs this before every email lookup/creation: apply the default
    # normalization, then collapse a +tag so demo+work@example.com and
    # demo@example.com resolve to the same account.
    normalized = cross_auth.normalize_email(email)
    local, sep, domain = normalized.partition("@")
    if sep and "+" in local:
        local = local.split("+", 1)[0]
    return f"{local}{sep}{domain}"


auth = CrossAuth(
    providers=[github],
    storage=secondary_storage,
    accounts_storage=accounts_storage,
    session_storage=session_storage,
    trusted_origins=[*SPA_TRUSTED_REDIRECT_HOSTS, *BACKEND_TRUSTED_REDIRECT_HOSTS],
    get_user_from_request=resolve_auth_user,
    default_next_url="/profile",
    # Explicit here; needed when redirect URIs must not be derived from the
    # incoming request (e.g. behind a proxy).
    base_url="http://127.0.0.1:8000",
    normalize_email=normalize_login_email,
    config={
        "account_linking": {"enabled": True, "allow_different_emails": True},
        "allowed_client_ids": [SPA_CLIENT_ID],
        "require_verified_email": True,
        "session": SESSION_CONFIG,
    },
)


@auth.before("authenticate")
def trim_password_login_email(
    event: BeforeAuthenticateEvent,
) -> BeforeAuthenticateEvent:
    # Trim only; lowercasing and +tag stripping run in normalize_email at lookup.
    return replace(event, email=event.email.strip())


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
def reject_blocked_provider_email(event: BeforeOAuthCallbackEvent) -> None:
    # require_verified_email already rejects unverified provider emails; this
    # hook adds a domain policy the flag can't express.
    email = event.validated_user_info.email
    if email is not None and email.endswith("@blocked.example"):
        raise CrossAuthException(
            "blocked_domain",
            "This email domain is not allowed for this demo.",
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
    # DELETE is required for the SPA's social-account disconnect call.
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
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
            cast(SessionRecord, record),
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


@app.post("/sessions/revoke-all")
def revoke_all_sessions_form(
    request: Request,
    user: Annotated[UserProtocol, Depends(auth.require_current_user)],
) -> RedirectResponse:
    # Revoke every session (including this one), then clear the cookie so the
    # browser is fully signed out rather than holding a now-dead cookie.
    auth.revoke_all_sessions(user_id=str(user.id))
    response = RedirectResponse(url="/", status_code=303)
    auth.logout(request, response=response)
    return response


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
    return JSONResponse(serialize_user(cast(User, user)))


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
                    cast(SessionRecord, record),
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


@app.post("/api/sessions/revoke-all")
def api_revoke_all_sessions(
    user: Annotated[UserProtocol, Depends(auth.require_current_user)],
) -> JSONResponse:
    # Revokes the calling bearer session too; the SPA drops its token afterward.
    revoked = auth.revoke_all_sessions(user_id=str(user.id))
    return JSONResponse({"ok": True, "revoked": revoked})
