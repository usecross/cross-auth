"""Session management policy, authoritative queries and commit notifications."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.contrib.auth import (
    BACKEND_SESSION_KEY,
    HASH_SESSION_KEY,
    get_user_model,
    logout,
)
from django.contrib.auth.base_user import AbstractBaseUser
from django.core.exceptions import ImproperlyConfigured
from django.db import transaction
from django.dispatch import Signal
from django.http import HttpRequest
from django.utils import timezone
from django.utils.crypto import constant_time_compare

from . import signals

if TYPE_CHECKING:
    from django.db.models import QuerySet

    from .models import Session
    from .sessions import SessionStore


@dataclass(frozen=True)
class SessionInfo:
    """One of the signed-in user's sessions, as ``list_sessions`` gives it."""

    # The session's public_id: safe to show and to post back to
    # revoke_session, unlike the session key.
    id: str
    # The provider of a Cross Auth sign-in, such as "google"; None for other
    # logins, such as Django's password login.
    login_method: str | None
    user_agent: str | None
    ip: str | None
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    # Whether this is the session of the request that listed it.
    is_current: bool


def _store(request: HttpRequest) -> SessionStore:
    from .sessions import SessionStore

    session = request.session
    if not isinstance(session, SessionStore):
        raise ImproperlyConfigured(
            "Listing and revoking sessions needs "
            "SESSION_ENGINE = 'cross_auth.django.sessions'"
        )

    return session


def _user(request: HttpRequest) -> AbstractBaseUser | None:
    user = request.user
    if not isinstance(user, AbstractBaseUser) or not user.is_authenticated:
        return None

    return user


def _signed_in(data: dict[str, Any], user: AbstractBaseUser) -> bool:
    """Whether Django's ``get_user()`` would still accept the session.

    A password change, or removing the session's backend from
    ``AUTHENTICATION_BACKENDS``, leaves the user's other sessions in the
    table, but Django treats them as logged out on their next request.
    """
    if data.get(BACKEND_SESSION_KEY) not in settings.AUTHENTICATION_BACKENDS:
        return False

    session_hash = data.get(HASH_SESSION_KEY)
    if not session_hash:
        return False

    if constant_time_compare(session_hash, user.get_session_auth_hash()):
        return True

    return any(
        constant_time_compare(session_hash, fallback)
        for fallback in user.get_session_auth_fallback_hash()
    )


def list_sessions(request: HttpRequest) -> list[SessionInfo]:
    """Return the signed-in user's active sessions, newest first.

    Expired sessions, and sessions that a password change or a removed
    authentication backend ended, are left out.
    Returns an empty list for anonymous requests.
    """
    store = _store(request)
    user = _user(request)
    if user is None:
        return []

    sessions = _unexpired(store, user).order_by("-created_at", "-last_activity")

    return [
        SessionInfo(
            id=str(session.public_id),
            login_method=session.login_method,
            user_agent=session.user_agent,
            ip=session.ip,
            created_at=session.created_at,
            last_activity=session.last_activity,
            expires_at=session.expire_date,
            is_current=session.session_key == store.session_key,
        )
        for session in sessions
        if _signed_in(session.get_decoded(), user)
    ]


def _send(signal: Signal, request: HttpRequest, **kwargs: object) -> None:
    signal.send(sender=get_user_model(), request=request, **kwargs)


def _revoked(
    request: HttpRequest,
    alias: str,
    user: AbstractBaseUser,
    *,
    scope: str,
    session_id: str | None,
    revoked_count: int,
) -> None:
    """Send ``session_revoked`` once the deletion is committed."""
    transaction.on_commit(
        lambda: _send(
            signals.session_revoked,
            request,
            user=user,
            scope=scope,
            session_id=session_id,
            revoked_count=revoked_count,
        ),
        using=alias,
        robust=False,
    )


def _unexpired(store: SessionStore, user: AbstractBaseUser) -> QuerySet[Session]:
    """The user's unexpired sessions, read from the database that deletes them.

    Reading them from a replica could miss a session that the primary still
    has, and leave it signed in.
    """
    return store.model.objects.using(store.alias).filter(
        user=user, expire_date__gt=timezone.now()
    )


def revoke_session(request: HttpRequest, session_id: str) -> bool:
    """Sign out one of the signed-in user's active sessions, named by its ``id``.

    Another user's session, an expired one, or one that Django already treats
    as logged out (see ``list_sessions``) is never touched. Revoking the
    current session logs the request out with Django's ``logout()``. Sends
    ``before_session_revoke`` and, once the session is signed out,
    ``session_revoked``. Returns whether a session was revoked.
    """
    store = _store(request)
    user = _user(request)
    if user is None:
        return False

    try:
        public_id = uuid.UUID(str(session_id))
    except ValueError:
        return False

    found = _unexpired(store, user).filter(public_id=public_id).first()
    if found is None or not _signed_in(found.get_decoded(), user):
        return False

    _send(
        signals.before_session_revoke,
        request,
        user_id=str(user.pk),
        scope="one",
        session_id=str(public_id),
    )

    # Looked up again: the session may have expired while receivers ran. By
    # public_id, not session key: a session keeps its public_id when its key
    # changes, even while it is being revoked.
    sessions = _unexpired(store, user).filter(public_id=public_id)
    if sessions.filter(session_key=store.session_key).exists():
        logout(request)
        revoked = 1
    else:
        revoked, _ = sessions.delete()

    if revoked:
        _revoked(
            request,
            store.alias,
            user,
            scope="one",
            session_id=str(public_id),
            revoked_count=revoked,
        )

    return revoked > 0


def revoke_other_sessions(request: HttpRequest) -> int:
    """Sign out the signed-in user's other active sessions, keeping this one.

    Sends ``before_session_revoke`` and, if any session was signed out,
    ``session_revoked``. Returns how many were revoked: only sessions that
    ``list_sessions`` shows count. Expired ones are left for
    ``clearsessions``, and those that Django already treats as logged out are
    removed on their next request.
    """
    store = _store(request)
    user = _user(request)
    if user is None:
        return 0

    _send(
        signals.before_session_revoke,
        request,
        user_id=str(user.pk),
        scope="others",
        session_id=None,
    )

    sessions = _unexpired(store, user)
    if store.session_key is not None:
        sessions = sessions.exclude(session_key=store.session_key)

    signed_in = [
        session.public_id
        for session in sessions
        if _signed_in(session.get_decoded(), user)
    ]

    deleted, _ = sessions.filter(public_id__in=signed_in).delete()
    if deleted:
        _revoked(
            request,
            store.alias,
            user,
            scope="others",
            session_id=None,
            revoked_count=deleted,
        )

    return deleted
