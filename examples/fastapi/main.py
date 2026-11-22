import os
import threading
import time
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, cast
from urllib.parse import urlencode

import cross_auth
from cross_web import HTTPRequest
import bcrypt
from fastapi import Depends, FastAPI, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
import qrcode
import qrcode.image.svg
from sqlalchemy import JSON, Column, UniqueConstraint
from sqlalchemy.pool import StaticPool
from sqlmodel import Field, Relationship, Session, SQLModel, create_engine

from cross_inertia import configure_inertia
from cross_inertia.fastapi import InertiaDep

from cross_auth import (
    OAuthClient,
    OAuthServer,
    SecondaryStorage,
    SessionConfig,
    SessionStatus,
)
from cross_auth import User as UserProtocol
from cross_auth._session import get_current_user as get_session_user
from cross_auth.exceptions import CrossAuthException, MFARequired
from cross_auth.fastapi import CrossAuth, SessionCookieMiddleware
from cross_auth.hooks import (
    AfterAuthenticateEvent,
    AfterLoginEvent,
    AfterLogoutEvent,
    AfterMFAVerifyEvent,
    AfterOAuthCallbackEvent,
    AfterTokenAuthorizationCodeEvent,
    AfterUserCreateEvent,
    BeforeAuthenticateEvent,
    BeforeOAuthCallbackEvent,
    BeforeUserCreateEvent,
)
from cross_auth.social_providers.github import GitHubProvider
from cross_auth.social_providers.google import GoogleProvider
from cross_auth.social_providers.oauth import OAuth2Provider
from cross_auth.storage.sqlmodel import (
    SQLModelAccountsStorage,
    SQLModelMFAFactor,
    SQLModelMFAStorage,
    SQLModelRecoveryCode,
    SQLModelSession,
    SQLModelUser,
    SQLModelSocialAccount,
    SQLModelSessionStorage,
)

APP_DIR = Path(__file__).parent
# The pages are React components in ../frontend, shared with the Django
# example and rendered through cross-inertia. `bun run build` there writes
# dist/, served below at /static/build/; with `bun run dev` running instead,
# pages load from the Vite dev server.
FRONTEND_DIR = APP_DIR.parent / "frontend"
configure_inertia(
    template_dir=str(APP_DIR / "templates"),
    vite_entry="src/app.tsx",
    vite_port=5174,
    vite_base="/static/build/",
    manifest_path=str(FRONTEND_DIR / "dist" / ".vite" / "manifest.json"),
    asset_url_prefix="/static/build",
)

SESSION_COOKIE_NAME = "cross_auth_example_session"
DEMO_EMAIL = "demo@example.com"
DEMO_PASSWORD = "password123"  # noqa: S105
GITHUB_MOCK_BASE_URL = "https://github-oauth-mock.fastapicloud.dev"
GITHUB_EMULATOR_URL = os.environ.get("GITHUB_EMULATOR_URL")
# Browser suites supply owned databases, callback origins and local providers.
BASE_URL = os.environ.get("EXAMPLE_BASE_URL", "http://127.0.0.1:8000")
DATABASE_URL = os.environ.get("EXAMPLE_DATABASE_URL")
GOOGLE_EMULATOR_URL = os.environ.get("GOOGLE_EMULATOR_URL")
SPA_DEMO_URL = "http://localhost:5173"
SPA_CLIENT_ID = "spa-example"
# Encrypts authenticator secrets. Set your own key outside the demo.
MFA_SECRET_KEY = os.environ.get("EXAMPLE_MFA_KEY", "example-mfa-key-do-not-use")
MFA_CHALLENGE_COOKIE = "mfa_challenge"
MAX_HOOK_EVENTS = 20
# Small page size so the demo's handful of sessions paginate visibly.
SESSIONS_PAGE_SIZE = 5

SPA_CORS_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    *os.environ.get("EXAMPLE_SPA_ORIGINS", "").split(),
]
CLIENT_REDIRECT_URIS = [
    "http://localhost:5173/callback",
    "http://127.0.0.1:5173/callback",
    "http://localhost:5173/link-callback",
    "http://127.0.0.1:5173/link-callback",
    "http://localhost:8000/link-callback",
    "http://127.0.0.1:8000/link-callback",
    *(
        f"{origin}/{callback}"
        for origin in os.environ.get("EXAMPLE_SPA_ORIGINS", "").split()
        for callback in ("callback", "link-callback")
    ),
]


class MemorySecondaryStorage(SecondaryStorage):
    def __init__(self) -> None:
        self.data: dict[str, tuple[str, float | None]] = {}
        self._lock = threading.Lock()

    def set(self, key: str, value: str, ttl: int | None = None) -> None:
        with self._lock:
            expires_at = time.monotonic() + ttl if ttl is not None else None
            self.data[key] = (value, expires_at)

    def _read(self, key: str, *, consume: bool) -> str | None:
        # The caller holds the lock across expiry checking and removal.
        entry = self.data.pop(key, None) if consume else self.data.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if expires_at is not None and time.monotonic() >= expires_at:
            self.data.pop(key, None)
            return None
        return value

    def get(self, key: str) -> str | None:
        with self._lock:
            return self._read(key, consume=False)

    def delete(self, key: str) -> None:
        with self._lock:
            self.data.pop(key, None)

    def pop(self, key: str) -> str | None:
        with self._lock:
            return self._read(key, consume=True)


# SQLModel base classes provide the common auth fields. The application owns
# primary keys, relationships, identity constraints, and provider credentials.
class SocialAccount(SQLModelSocialAccount, table=True):
    __table_args__ = (UniqueConstraint("provider", "provider_user_id"),)

    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    access_token: str | None = None
    refresh_token: str | None = None
    access_token_expires_at: datetime | None = None
    refresh_token_expires_at: datetime | None = None
    scope: str | None = None
    user: "User" = Relationship(back_populates="social_accounts")


class WelcomeNote(SQLModel, table=True):
    # AccountsStore.build_user adds one of these so the demo has a
    # related row that joins the same commit as the new user.
    id: int | None = Field(default=None, primary_key=True)
    user_id: int | None = Field(default=None, foreign_key="user.id", nullable=False)
    message: str

    user: "User" = Relationship(back_populates="welcome_notes")


class User(SQLModelUser, table=True):
    id: int | None = Field(default=None, primary_key=True)
    email: str = Field(index=True)
    email_verified: bool = False
    # Extra demo column populated by the user.create hook.
    display_name: str | None = None
    # Clear it to suspend the user: user_can_authenticate refuses their logins
    # and their sessions until it is set again.
    is_active: bool = True

    social_accounts: list[SocialAccount] = Relationship(
        back_populates="user", sa_relationship_kwargs={"lazy": "selectin"}
    )
    welcome_notes: list[WelcomeNote] = Relationship(back_populates="user")


class SessionRecord(SQLModelSession, table=True):
    id: int | None = Field(default=None, primary_key=True)
    user_id: str = Field(index=True)


# Two-factor authentication: confirmed authenticators and hashed recovery codes.
class MFAFactor(SQLModelMFAFactor, table=True):
    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", index=True)
    data: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))


class RecoveryCode(SQLModelRecoveryCode, table=True):
    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", index=True)


# In-memory SQLite. StaticPool keeps a single shared connection (a fresh
# connection would open an empty database); check_same_thread lets FastAPI's
# threadpooled sync endpoints reach it. Restarting the process drops every
# table, so the demo keeps its "restart resets everything" property.
engine = (
    create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    if DATABASE_URL is None
    else create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
)
SQLModel.metadata.create_all(engine)

# StaticPool shares one SQLite connection, which SQLite can't use from two
# threads at once. Serialize each SQL session independently of the secondary
# storage lock; neither storage boundary holds the other's lock.
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
        **kwargs: Any,
    ) -> User:
        user = super().build_user(session=session, **kwargs)
        session.add(WelcomeNote(user=user, message=f"Welcome, {user.display_name}!"))
        return user


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
        "login_method": record.login_method,
        # Int PK vs. the string id resolved from the cookie — compare as strings.
        "current": str(record.id) == current_session_id,
    }


def get_error_message(error: str | None) -> str | None:
    if error == "invalid_credentials":
        return "The demo credentials were invalid."
    if error == "account_inactive":
        return "This account is inactive."
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


def user_can_authenticate(user: UserProtocol) -> bool:
    return isinstance(user, User) and user.is_active


def resolve_auth_user(request: HTTPRequest) -> User | None:
    session_user = get_session_user(
        request,
        session_storage,
        accounts_storage,
        SESSION_CONFIG,
        user_can_authenticate=user_can_authenticate,
    )
    if session_user is not None:
        return cast(User, session_user)

    return None


github = GitHubProvider(
    client_id="demo-client",
    client_secret="demo-secret",
    authorization_endpoint=f"{GITHUB_EMULATOR_URL or GITHUB_MOCK_BASE_URL}/login/oauth/authorize",
    token_endpoint=f"{GITHUB_EMULATOR_URL or GITHUB_MOCK_BASE_URL}/login/oauth/access_token",
    api_base_url=(GITHUB_EMULATOR_URL or f"{GITHUB_MOCK_BASE_URL}/api"),
)

providers: list[OAuth2Provider] = [github]

if GOOGLE_EMULATOR_URL is not None:

    class EmulatedGoogleProvider(GoogleProvider):
        # The emulator signs ID tokens with its own URL as issuer. Signature,
        # audience, nonce and PKCE checks are unchanged.
        issuer = GOOGLE_EMULATOR_URL

    providers.append(
        EmulatedGoogleProvider(
            client_id=os.environ["GOOGLE_CLIENT_ID"],
            client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
            authorization_endpoint=f"{GOOGLE_EMULATOR_URL}/o/oauth2/v2/auth",
            token_endpoint=f"{GOOGLE_EMULATOR_URL}/oauth2/token",
            jwks_uri=f"{GOOGLE_EMULATOR_URL}/oauth2/v3/certs",
        )
    )

secondary_storage = MemorySecondaryStorage()
# Swap for Redis: from cross_auth.storage.redis import RedisStorage
# storage = RedisStorage.from_url(os.environ["REDIS_URL"])
accounts_storage = AccountsStore(session_factory=open_db_session)
session_storage = SQLModelSessionStorage(SessionRecord, session_factory=open_db_session)
mfa_storage = SQLModelMFAStorage(
    MFAFactor, RecoveryCode, session_factory=open_db_session
)


def seed_demo_user() -> None:
    # The password form's demo accounts. In-memory SQLite starts empty on every
    # run, so this reseeds the durable password users at each startup.
    with open_db_session() as session:
        session.add(
            User(
                email=DEMO_EMAIL,
                email_verified=True,
                hashed_password=bcrypt.hashpw(
                    DEMO_PASSWORD.encode(), bcrypt.gensalt()
                ).decode(),
                display_name="Demo User",
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


OAUTH_CLIENTS = {
    SPA_CLIENT_ID: OAuthClient(
        client_id=SPA_CLIENT_ID,
        redirect_uris=(*CLIENT_REDIRECT_URIS, f"{BASE_URL}/link-callback"),
    )
}

auth = CrossAuth(
    providers=providers,
    storage=secondary_storage,
    accounts_storage=accounts_storage,
    session_storage=session_storage,
    get_user_from_request=resolve_auth_user,
    user_can_authenticate=user_can_authenticate,
    mfa_storage=mfa_storage,
    default_next_url="/profile",
    # Explicit here; needed when redirect URIs must not be derived from the
    # incoming request (e.g. behind a proxy).
    base_url=BASE_URL,
    normalize_email=normalize_login_email,
    # The SPA and the profile page's "Link Google account" use the OAuth
    # server's /authorize, /token, /link and /finalize-link routes.
    oauth_server=OAuthServer(
        get_client=OAUTH_CLIENTS.get,
        # Deprecated and removed in 1.0: the SPA's password form still uses
        # the OAuth password grant at /token, which warns on each use.
        password_grant=True,
    ),
    config={
        "account_linking": {"enabled": True, "allow_different_emails": True},
        "require_verified_email": True,
        "session": SESSION_CONFIG,
        "mfa": {
            "issuer": "Cross-Auth FastAPI example",
            # Provider sign-ins that need a code are sent here.
            "verify_url": "/login/2fa",
            "secret_keys": [MFA_SECRET_KEY],
            "challenge_cookie": MFA_CHALLENGE_COOKIE,
        },
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


@auth.after("user.create")
def audit_created_user(event: AfterUserCreateEvent) -> None:
    # The adapter transaction has committed before this public hook runs.
    record_hook_event(
        "after:user.create",
        user_id=str(event.user.id),
        email=event.user.email or "",
    )


@auth.before("user.create")
def populate_user_fields(event: BeforeUserCreateEvent) -> BeforeUserCreateEvent:
    name = event.user_info.get("name")
    display_name = str(name) if name else event.email.split("@", 1)[0]
    return replace(
        event,
        extra_fields={**event.extra_fields, "display_name": display_name},
    )


@auth.before("user.create")
def reject_banned_signup(event: BeforeUserCreateEvent) -> None:
    if event.email.endswith("@banned.example"):
        raise CrossAuthException(
            "signup_blocked",
            "Signups from that domain are not allowed.",
        )


@auth.after("login")
def audit_login(event: AfterLoginEvent) -> None:
    if event.response is not None:
        event.response.headers = {
            **(event.response.headers or {}),
            "X-Cross-Auth-Hook": "login",
        }
    record_hook_event("after:login", user_id=event.user_id, credential=event.credential)


@auth.after("mfa.verify")
def audit_mfa_verify(event: AfterMFAVerifyEvent) -> None:
    record_hook_event(
        "after:mfa.verify",
        user_id=event.user_id,
        purpose=event.purpose,
        method=event.method,
        result="success" if event.success else (event.reason or "failed"),
    )


@auth.after("logout")
def audit_session_logout(event: AfterLogoutEvent) -> None:
    record_hook_event("after:logout", session_id=str(event.session_record.id))


@auth.before("oauth.callback")
def reject_blocked_provider_email(event: BeforeOAuthCallbackEvent) -> None:
    # require_verified_email already rejects unverified provider emails; this
    # hook adds a domain policy the flag can't express.
    email = event.validated_user_info.email
    if email is not None and email.endswith("@blocked.example"):
        raise CrossAuthException(
            "blocked_domain",
            "This email domain is not allowed for this demo.",
            status_code=403,
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
# Sessions use update_age (sliding expiry), so rolled cookies need a way onto
# outgoing responses — including the RedirectResponses these handlers return.
app.add_middleware(SessionCookieMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=SPA_CORS_ORIGINS,
    allow_credentials=True,
    # DELETE is required for the SPA's social-account disconnect call.
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)
app.include_router(auth.router, prefix="/auth")
app.mount(
    "/static/build",
    StaticFiles(directory=FRONTEND_DIR / "dist", check_dir=False),
    name="frontend",
)


@app.get("/")
def home(
    inertia: InertiaDep,
    user: Annotated[UserProtocol | None, Depends(auth.get_current_user)],
    error: str | None = None,
):
    return inertia.render(
        "fastapi/Home",
        {
            "demo_email": DEMO_EMAIL,
            "demo_password": DEMO_PASSWORD,
            "error_message": get_error_message(error),
            "github_login_url": "/auth/github/login?next=/profile",
            "github_mock_base_url": GITHUB_MOCK_BASE_URL,
            "google_enabled": GOOGLE_EMULATOR_URL is not None,
            "hook_events": hook_events[:5],
            "spa_client_id": SPA_CLIENT_ID,
            "spa_demo_url": SPA_DEMO_URL,
            "user": None if user is None else {"id": user.id, "email": user.email},
        },
    )


@app.post("/login")
def login(
    request: Request,
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
) -> RedirectResponse:
    try:
        user = auth.authenticate(email, password)
    except CrossAuthException:
        # The password matched, but user_can_authenticate refused the user.
        return RedirectResponse(url="/?error=account_inactive", status_code=303)
    if user is None:
        return RedirectResponse(url="/?error=invalid_credentials", status_code=303)

    response = RedirectResponse(url="/profile", status_code=303)
    try:
        auth.login(
            str(user.id),
            response=response,
            metadata={"user_agent": request.headers.get("User-Agent")},
            login_method="password",
        )
    except MFARequired as required:
        # The password matched; no session exists until the code does too.
        # The challenge travels in an HttpOnly cookie that /auth/mfa/verify reads.
        assert required.challenge is not None
        pending = RedirectResponse(url="/login/2fa", status_code=303)
        pending.set_cookie(
            MFA_CHALLENGE_COOKIE,
            required.challenge,
            max_age=300,
            path="/",
            httponly=True,
            samesite="lax",
        )
        return pending
    return response


MFA_ERRORS = {
    "invalid_code": "That code is not correct. Try again.",
    "invalid_challenge": "This sign-in has expired.",
    "mfa_locked": "Too many wrong codes. Wait a few minutes, then sign in again.",
    "invalid_password": "That password is not correct.",
    "email_not_verified": "Verify your email address before turning on two-factor authentication.",
    "enrollment_not_found": "That took too long. Start again.",
}

# The two-factor pages in ../frontend/src/pages/two-factor are shared with the
# Django example; each backend passes its own URLs and picks its layout.
SITE = "fastapi"


@app.get("/login/2fa")
def login_two_factor(request: Request, inertia: InertiaDep, error: str | None = None):
    # Posts to the router's POST /auth/mfa/verify, which finishes the sign-in
    # and sends wrong codes back here with ?error=.
    expired = MFA_CHALLENGE_COOKIE not in request.cookies or error in (
        "invalid_challenge",
        "mfa_locked",
    )
    return inertia.render(
        "two-factor/Verify",
        {
            "site": SITE,
            "error": MFA_ERRORS.get(error or "", error),
            "expired": expired,
            "methods": [] if expired else ["totp", "recovery_code"],
            "next": "",
            "urls": {"verify": "/auth/mfa/verify", "sign_in": "/"},
        },
    )


def _qr_svg(uri: str) -> str:
    # Rendered here, never by a QR service: the URI contains the secret.
    image = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
    return image.to_string(encoding="unicode")


def _two_factor_page(
    request: Request,
    inertia: InertiaDep,
    *,
    error: str | None = None,
    status_code: int = 200,
):
    mfa = auth.get_mfa_status(request)
    return inertia.render(
        "two-factor/Settings",
        {
            "site": SITE,
            "error": MFA_ERRORS.get(error or "", error),
            "mfa": {
                "enabled": mfa.enabled,
                "recovery_codes_remaining": mfa.recovery_codes_remaining,
                "factors": [
                    {
                        "id": factor.id,
                        "name": factor.name or "Authenticator app",
                        "added": f"{factor.created_at.day} {factor.created_at:%b %Y}",
                        "remove_url": f"/settings/2fa/{factor.id}/remove",
                    }
                    for factor in mfa.factors
                ],
            },
            "urls": {
                "start": "/settings/2fa/start",
                "recovery_codes": "/settings/2fa/recovery-codes",
                "back": "/profile",
            },
        },
        status_code=status_code,
    )


def _mfa_refused(request: Request, inertia: InertiaDep, error: CrossAuthException):
    # Changing 2FA needs a recent sign-in; send the user to confirm it is them.
    if error.error == "reauthentication_required":
        return RedirectResponse(url="/settings/confirm-identity", status_code=303)
    return _two_factor_page(
        request, inertia, error=error.error, status_code=error.status_code
    )


def _enroll_page(
    inertia: InertiaDep,
    *,
    enrollment_id: str,
    secret: str,
    otpauth_uri: str,
    error: str | None = None,
):
    return inertia.render(
        "two-factor/Enroll",
        {
            "site": SITE,
            "enrollment_id": enrollment_id,
            "secret": secret,
            "otpauth_uri": otpauth_uri,
            "qr_svg": _qr_svg(otpauth_uri),
            "error": error,
            "urls": {"confirm": "/settings/2fa/confirm", "cancel": "/settings/2fa"},
        },
        status_code=400 if error else 200,
    )


def _codes_page(inertia: InertiaDep, codes: list[str]):
    return inertia.render(
        "two-factor/RecoveryCodes",
        {"site": SITE, "codes": codes, "urls": {"done": "/settings/2fa"}},
    )


@app.get("/settings/2fa")
def two_factor_settings(
    request: Request,
    inertia: InertiaDep,
    user: Annotated[UserProtocol | None, Depends(auth.get_current_user)],
):
    if user is None:
        return RedirectResponse(url="/", status_code=303)
    return _two_factor_page(request, inertia)


@app.post("/settings/2fa/start")
def two_factor_start(
    request: Request,
    inertia: InertiaDep,
    user: Annotated[UserProtocol, Depends(auth.require_current_user)],
):
    try:
        enrollment = auth.start_totp_enrollment(request, name="Authenticator app")
    except CrossAuthException as error:
        return _mfa_refused(request, inertia, error)
    return _enroll_page(
        inertia,
        enrollment_id=enrollment.enrollment_id,
        secret=enrollment.secret,
        otpauth_uri=enrollment.otpauth_uri,
    )


@app.post("/settings/2fa/confirm")
def two_factor_confirm(
    request: Request,
    inertia: InertiaDep,
    user: Annotated[UserProtocol, Depends(auth.require_current_user)],
    enrollment_id: Annotated[str, Form()],
    code: Annotated[str, Form()],
    secret: Annotated[str, Form()],
    otpauth_uri: Annotated[str, Form()],
):
    try:
        confirmed = auth.confirm_totp_enrollment(
            request, enrollment_id=enrollment_id, code=code
        )
    except CrossAuthException as error:
        if error.error != "invalid_code":
            return _mfa_refused(request, inertia, error)
        # The enrollment waits ten minutes: show the same secret again.
        return _enroll_page(
            inertia,
            enrollment_id=enrollment_id,
            secret=secret,
            otpauth_uri=otpauth_uri,
            error=MFA_ERRORS["invalid_code"],
        )
    if confirmed.recovery_codes is None:
        return RedirectResponse(url="/settings/2fa", status_code=303)
    return _codes_page(inertia, confirmed.recovery_codes)


@app.post("/settings/2fa/recovery-codes")
def two_factor_recovery_codes(
    request: Request,
    inertia: InertiaDep,
    user: Annotated[UserProtocol, Depends(auth.require_current_user)],
):
    try:
        codes = auth.regenerate_recovery_codes(request)
    except CrossAuthException as error:
        return _mfa_refused(request, inertia, error)
    return _codes_page(inertia, codes)


@app.post("/settings/2fa/{factor_id}/remove")
def two_factor_remove(
    request: Request,
    inertia: InertiaDep,
    factor_id: str,
    user: Annotated[UserProtocol, Depends(auth.require_current_user)],
):
    try:
        auth.remove_mfa_factor(request, factor_id)
    except CrossAuthException as error:
        return _mfa_refused(request, inertia, error)
    return RedirectResponse(url="/settings/2fa", status_code=303)


def _confirm_identity_page(
    inertia: InertiaDep, user: UserProtocol, *, error: str | None = None
):
    return inertia.render(
        "two-factor/ConfirmIdentity",
        {
            "site": SITE,
            "error": error,
            "has_password": user.hashed_password is not None,
            "urls": {
                "submit": "/settings/confirm-identity",
                "cancel": "/settings/2fa",
            },
        },
        status_code=400 if error else 200,
    )


@app.get("/settings/confirm-identity")
def confirm_identity_page(
    inertia: InertiaDep,
    user: Annotated[UserProtocol | None, Depends(auth.get_current_user)],
):
    if user is None:
        return RedirectResponse(url="/", status_code=303)
    return _confirm_identity_page(inertia, user)


@app.post("/settings/confirm-identity")
def confirm_identity(
    request: Request,
    inertia: InertiaDep,
    user: Annotated[UserProtocol, Depends(auth.require_current_user)],
    password: Annotated[str, Form()] = "",
    code: Annotated[str, Form()] = "",
):
    try:
        auth.reauthenticate(request, password=password or None, code=code or None)
    except CrossAuthException as error:
        return _confirm_identity_page(
            inertia,
            user,
            error=MFA_ERRORS.get(error.error, error.error_description),
        )
    return RedirectResponse(url="/settings/2fa", status_code=303)


@app.post("/logout")
def logout(request: Request) -> RedirectResponse:
    response = RedirectResponse(url="/", status_code=303)
    auth.logout(request, response=response)
    return response


@app.get("/profile")
def profile(
    inertia: InertiaDep,
    user: Annotated[UserProtocol | None, Depends(auth.get_current_user)],
):
    if user is None:
        return RedirectResponse(url="/", status_code=303)

    return inertia.render(
        "fastapi/Profile",
        {
            "google_enabled": GOOGLE_EMULATOR_URL is not None,
            "hook_events": hook_events[:5],
            "user": serialize_user(cast(User, user)),
            "spa_client_id": SPA_CLIENT_ID,
        },
    )


@app.get("/sessions")
def sessions_page(
    request: Request,
    inertia: InertiaDep,
    user: Annotated[UserProtocol | None, Depends(auth.get_current_user)],
    status: SessionStatus | None = None,
    cursor: str | None = None,
):
    if user is None:
        return RedirectResponse(url="/", status_code=303)

    current_session = auth.get_current_session(request)
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

    return inertia.render(
        "fastapi/Sessions",
        {
            "current_status": status,
            "sessions": sessions,
            "user": {"email": user.email},
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
) -> RedirectResponse:
    current_session = auth.get_current_session(request)
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
    auth.revoke_all_sessions(user_id=str(user.id))
    response = RedirectResponse(url="/", status_code=303)
    auth.logout(request, response=response)
    return response


@app.get("/hooks")
def hooks_page(inertia: InertiaDep):
    return inertia.render("fastapi/Hooks", {"hook_events": hook_events})


@app.get("/link-callback")
def link_callback(inertia: InertiaDep):
    return inertia.render("fastapi/LinkCallback", {"next_url": "/profile"})


@app.get("/api/me")
def api_me_session(
    user: Annotated[UserProtocol, Depends(auth.require_current_user)],
) -> JSONResponse:
    return JSONResponse(serialize_user(cast(User, user)))


@app.get("/api/sessions")
def api_sessions(
    request: Request,
    user: Annotated[UserProtocol, Depends(auth.require_current_user)],
    status: SessionStatus | None = None,
    cursor: str | None = None,
) -> JSONResponse:
    current_session = auth.get_current_session(request)
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


# auth.router serves JSON clients the caller's sessions as well:
# GET /auth/sessions, DELETE /auth/sessions/{session_id} and
# POST /auth/sessions/revoke-others. /api/sessions above adds the demo's
# display fields and status filter for the session dashboard's e2e test.


@app.post("/api/sessions/revoke-all")
def api_revoke_all_sessions(
    user: Annotated[UserProtocol, Depends(auth.require_current_user)],
) -> JSONResponse:
    # Revokes the calling bearer session too; the SPA drops its token afterward.
    revoked = auth.revoke_all_sessions(user_id=str(user.id))
    return JSONResponse({"ok": True, "revoked": revoked})
