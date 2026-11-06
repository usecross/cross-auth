"""Database sessions that know their user, login method and device.

Opt in with two settings, in place of Django's session engine and middleware::

    SESSION_ENGINE = "cross_auth.django.sessions"
    MIDDLEWARE = [..., "cross_auth.django.sessions.SessionMiddleware", ...]

Sessions are then stored in ``cross_auth.django.models.Session``. Each save
fills its columns from the session's data (the user, and the provider of a
Cross Auth sign-in) and from the request (user agent and IP), so a user's
sessions can be listed and revoked with ``list_sessions``,
``revoke_session`` and ``revoke_other_sessions``. Only the ``db`` engine is
provided; there is no cache or ``cached_db`` variant.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, replace
from datetime import datetime
from typing import TYPE_CHECKING, Any

from asgiref.sync import sync_to_async
from django.contrib.auth import (
    BACKEND_SESSION_KEY,
    SESSION_KEY,
    get_user_model,
)
from django.contrib.sessions.backends.base import CreateError, UpdateError
from django.contrib.sessions.backends.db import SessionStore as DatabaseSessionStore
from django.contrib.sessions.middleware import (
    SessionMiddleware as DjangoSessionMiddleware,
)
from django.db import DatabaseError, IntegrityError, router, transaction
from django.http import HttpRequest, HttpResponse
from django.utils import timezone

from ._session_management import SessionInfo as SessionInfo
from ._session_management import list_sessions as list_sessions
from ._session_management import revoke_other_sessions as revoke_other_sessions
from ._session_management import revoke_session as revoke_session
from .backends import BACKEND
from .conf import get_settings

if TYPE_CHECKING:
    from .models import Session

    # django-stubs makes the store generic in its model; Django's is not.
    _DatabaseSessionStore = DatabaseSessionStore[Session]
else:
    _DatabaseSessionStore = DatabaseSessionStore

# Framework-owned session keys start with an underscore, like Django's own
# ``_auth_user_id``. Cross Auth's login stores the provider here.
LOGIN_METHOD_SESSION_KEY = "_cross_auth_login_method"

_USER_AGENT_MAX_LENGTH = 512

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _Client:
    user_agent: str | None
    ip: str | None


@dataclass(frozen=True)
class _Row:
    """What a store knows of the row it loaded or saved."""

    session_key: str
    last_activity: datetime

    @classmethod
    def of(cls, session: Session) -> _Row:
        return cls(session.session_key, session.last_activity)


def _clean_user_agent(value: str | None) -> str | None:
    """Return a user agent fit to store and show, or ``None``.

    Control and other unprintable characters become spaces (PostgreSQL also
    refuses NUL), runs of whitespace collapse, and the result is cut to the
    column's 512 characters.
    """
    if not value:
        return None

    printable = "".join(char if char.isprintable() else " " for char in value)
    return " ".join(printable.split())[:_USER_AGENT_MAX_LENGTH].strip() or None


def _clean_ip(value: str | None) -> str | None:
    """Return the normalized IP address in ``value``, or ``None``.

    IPv6 zone IDs are dropped and IPv4-mapped IPv6 addresses become IPv4.
    """
    if not value:
        return None

    try:
        address = ipaddress.ip_address(value.split("%", 1)[0].strip())
    except ValueError:
        return None

    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return str(address.ipv4_mapped)

    return str(address)


class SessionStore(_DatabaseSessionStore):
    """Django's database session store, saving to Cross Auth's ``Session``.

    Every save recomputes ``user`` from ``_auth_user_id`` and
    ``login_method`` from the session's backend: the provider Cross Auth's
    login recorded while the session is logged in with ``CrossAuthBackend``,
    ``None`` for any other backend. A later password login in the same
    session therefore clears it.

    ``public_id`` and ``created_at`` belong to a sign-in: each login (any
    ``user_logged_in``) starts new ones, and a new session key without a
    login, such as ``update_session_auth_hash()`` after a password change,
    keeps them.
    """

    def __init__(self, session_key: str | None = None) -> None:
        super().__init__(session_key)
        self.alias = router.db_for_write(self.model)
        self._client: _Client | None = None
        # The row this store loaded or saved, if it knows it.
        self._row: _Row | None = None
        # Set by user_logged_in until the next save writes a new sign-in.
        self._login_pending = False

    @classmethod
    def get_model_class(cls) -> type[Session]:
        from .models import Session

        return Session

    def set_client(self, *, user_agent: str | None, ip: str | None) -> None:
        """Record the device of the current request, sanitized.

        ``SessionMiddleware`` calls this. Saves and activity updates write
        it; a store without it, such as one created outside a request, keeps
        the stored values.
        """
        self._client = _Client(_clean_user_agent(user_agent), _clean_ip(ip))

    def create_model_instance(self, data: dict[str, Any]) -> Session:
        now = timezone.now()
        user_id = data.get(SESSION_KEY)
        login_method = data.get(LOGIN_METHOD_SESSION_KEY)
        # django-stubs leaves out the store's private methods.
        key = self._get_or_create_session_key()  # ty: ignore[unresolved-attribute]
        session = self.model(
            session_key=key,
            session_data=self.encode(data),
            expire_date=self.get_expiry_date(),
            user_id=(
                None
                if user_id is None
                else get_user_model()._meta.pk.to_python(user_id)
            ),
            login_method=(
                login_method
                if data.get(BACKEND_SESSION_KEY) == BACKEND
                and isinstance(login_method, str)
                else None
            ),
            created_at=now,
            last_activity=now,
        )
        if self._client is not None:
            session.user_agent = self._client.user_agent
            session.ip = self._client.ip

        return session

    async def acreate_model_instance(self, data: dict[str, Any]) -> Session:
        return await sync_to_async(self.create_model_instance)(data)

    def save(self, must_create: bool = False) -> None:
        # Django's save(), except that an update leaves public_id, created_at
        # and, without a client, the device as they are (see _write), and
        # only a clash of session keys is a CreateError: Django's create()
        # retries those forever, which a user deleted mid-login must not cause.
        if self.session_key is None:
            return self.create()

        data = self._get_session(  # ty: ignore[unresolved-attribute]
            no_load=must_create
        )
        session = self.create_model_instance(data)
        using = self.alias

        try:
            with transaction.atomic(using=using):
                if must_create:
                    session.save(force_insert=True, using=using)
                    written = True
                else:
                    written = self._write(session.session_key, session, using)
        except IntegrityError:
            if must_create and self.exists(session.session_key):
                raise CreateError
            raise
        except DatabaseError:
            if not must_create:
                raise UpdateError
            raise

        if not written:
            # Like Django: the row was deleted since this request loaded it.
            raise UpdateError

        self._saved(session)

    async def asave(self, must_create: bool = False) -> None:
        await sync_to_async(self.save)(must_create)

    def cycle_key(self) -> None:
        # Django saves the data under a new key and then deletes the old row.
        # Moving the stored row to the new key instead keeps a single row for
        # the session, with its public_id and created_at, and a session that
        # was revoked meanwhile stays revoked: there is no row left to move.
        data = self._session  # ty: ignore[unresolved-attribute]
        key = self.session_key
        if key is None:
            # Nothing is stored under the cookie's key.
            return super().cycle_key()

        while True:
            self._session_key = (
                self._get_new_session_key()  # ty: ignore[unresolved-attribute]
            )
            session = self.create_model_instance(data)
            using = self.alias
            try:
                with transaction.atomic(using=using):
                    moved = self._write(key, session, using)
            except IntegrityError:
                if self.exists(session.session_key):
                    # Another session took the new key first.
                    continue
                raise
            break

        if not moved:
            # Revoked or logged out since this request loaded it: start an
            # empty session rather than bring the old one back.
            self._session_cache = {}
            self.create()
            return

        self.modified = True
        self._saved(session)

    async def acycle_key(self) -> None:
        await sync_to_async(self.cycle_key)()

    def _write(self, key: str, session: Session, using: str) -> bool:
        """Write ``session`` over the stored row of ``key``, if there is one.

        The row moves to ``session``'s key if that differs. It keeps its
        ``public_id`` and ``created_at`` unless a login is pending, and its
        device unless the store has a client.
        """
        columns: dict[str, object] = {
            "session_data": session.session_data,
            "expire_date": session.expire_date,
            "user_id": session.user_id,
            "login_method": session.login_method,
            "last_activity": session.last_activity,
        }

        if session.session_key != key:
            columns["session_key"] = session.session_key
        if self._client is not None:
            columns.update(user_agent=session.user_agent, ip=session.ip)
        if self._login_pending:
            columns.update(public_id=session.public_id, created_at=session.created_at)

        rows = self.model.objects.using(using).filter(session_key=key)

        return rows.update(**columns) > 0

    def _saved(self, session: Session) -> None:
        self._row = _Row.of(session)
        self._login_pending = False

    def _logged_in(self) -> None:
        self._login_pending = True

    def _get_session_from_db(self) -> Session | None:
        session = (
            self.model.objects.using(self.alias)
            .filter(session_key=self.session_key, expire_date__gt=timezone.now())
            .first()
        )
        if session is None:
            self._session_key = None
        self._loaded(session)

        return session

    async def _aget_session_from_db(self) -> Session | None:
        return await sync_to_async(self._get_session_from_db)()

    def exists(self, session_key: str) -> bool:
        return (
            self.model.objects.using(self.alias)
            .filter(session_key=session_key)
            .exists()
        )

    async def aexists(self, session_key: str) -> bool:
        return await sync_to_async(self.exists)(session_key)

    def delete(self, session_key: str | None = None) -> None:
        key = session_key if session_key is not None else self.session_key
        if key is not None:
            self.model.objects.using(self.alias).filter(session_key=key).delete()

    async def adelete(self, session_key: str | None = None) -> None:
        await sync_to_async(self.delete)(session_key)

    @classmethod
    def clear_expired(cls) -> None:
        model = cls.get_model_class()
        model.objects.using(router.db_for_write(model)).filter(
            expire_date__lt=timezone.now()
        ).delete()

    @classmethod
    async def aclear_expired(cls) -> None:
        await sync_to_async(cls.clear_expired)()

    def _loaded(self, session: Session | None) -> None:
        if session is not None:
            self._row = _Row.of(session)

    def record_activity(self) -> None:
        """Update the stored ``last_activity``, at most once per interval.

        Only for a session this store loaded or saved and still holds, so a
        request that never touched the session writes nothing. The interval is
        ``CROSS_AUTH["SESSION_ACTIVITY_INTERVAL"]``. The update is best-effort:
        a database error is logged, not raised.
        """
        row = self._row
        if row is None or row.session_key != self.session_key:
            return

        now = timezone.now()
        since = now - get_settings().session_activity_interval
        if row.last_activity > since:
            return

        changes: dict[str, object] = {"last_activity": now}
        if self._client is not None:
            changes.update(user_agent=self._client.user_agent, ip=self._client.ip)
        using = self.alias
        # Only if no other request of the session has updated it since, so
        # concurrent requests write once, and never an older time.
        rows = self.model.objects.using(using).filter(
            session_key=row.session_key, last_activity__lte=since
        )
        try:
            with transaction.atomic(using=using):
                updated = rows.update(**changes)
        except DatabaseError:
            logger.warning("Could not record a session's activity", exc_info=True)
            return

        if updated:
            self._row = replace(row, last_activity=now)


def _start_sign_in(
    sender: object, request: HttpRequest | None = None, **kwargs: Any
) -> None:
    """``user_logged_in`` receiver: the login's session gets a new sign-in.

    Django's ``login()`` sends it after giving the session its new key, so
    the save that follows writes a new ``public_id`` and ``created_at``.
    """
    session = getattr(request, "session", None)
    if isinstance(session, SessionStore):
        session._logged_in()


class SessionMiddleware(DjangoSessionMiddleware):
    """Django's ``SessionMiddleware`` for ``cross_auth.django.sessions``.

    It also gives the session its request's user agent and IP, and updates
    the session's ``last_activity`` (throttled) when nothing else saves it.
    The IP is ``REMOTE_ADDR``, never a forwarding header; behind a proxy,
    set ``REMOTE_ADDR`` from the header your proxy sets, in middleware that
    runs before this one, or every session shows the proxy's address.
    """

    def process_request(self, request: HttpRequest) -> None:
        super().process_request(request)
        session = request.session
        if isinstance(session, SessionStore):
            session.set_client(
                user_agent=request.META.get("HTTP_USER_AGENT"),
                ip=request.META.get("REMOTE_ADDR"),
            )

    def process_response(
        self, request: HttpRequest, response: HttpResponse
    ) -> HttpResponse:
        response = super().process_response(request, response)
        session = getattr(request, "session", None)
        # Like Django's save, skipped for server errors.
        if isinstance(session, SessionStore) and response.status_code < 500:
            session.record_activity()

        return response
