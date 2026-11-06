"""Response delivery for cookie effects produced by FastAPI session reads."""

from __future__ import annotations

import warnings
from dataclasses import dataclass, field

from cross_web import Cookie
from fastapi import Request, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

_COOKIE_SINK_STATE_KEY = "cross_auth_cookie_sink"


def set_cookie(response: Response, cookie: Cookie) -> None:
    response.set_cookie(
        key=cookie.name,
        value=cookie.value,
        max_age=cookie.max_age,
        path=cookie.path or "/",
        domain=cookie.domain,
        secure=cookie.secure,
        httponly=cookie.httponly,
        samesite=cookie.samesite,
    )


@dataclass
class _CookieSink:
    cookies: list[Cookie] = field(default_factory=list)

    def apply(self, message: Message) -> None:
        headers: list[tuple[bytes, bytes]] = message.setdefault("headers", [])
        for cookie in self.cookies:
            prefix = f"{cookie.name}=".encode("latin-1")
            if any(
                name.lower() == b"set-cookie" and value.startswith(prefix)
                for name, value in headers
            ):
                continue
            scratch = Response()
            set_cookie(scratch, cookie)
            headers.append(
                (b"set-cookie", scratch.headers["set-cookie"].encode("latin-1"))
            )


def queue_rolled_cookie(request: Request, cookie: Cookie) -> None:
    sink = request.scope.setdefault("state", {}).get(_COOKIE_SINK_STATE_KEY)
    if not isinstance(sink, _CookieSink):
        warnings.warn(
            "A sliding session refreshed but SessionCookieMiddleware is "
            "not installed, so the rolled session cookie cannot reach the "
            "browser and the user will be logged out at the cookie's "
            "original Max-Age. Add "
            "`app.add_middleware(SessionCookieMiddleware)`.",
            stacklevel=2,
        )
        return
    sink.cookies.append(cookie)


class SessionCookieMiddleware:
    """Deliver rolled sliding-session cookies, including on direct responses.

    Install once with ``app.add_middleware(SessionCookieMiddleware)`` when
    sessions use ``update_age``. A cookie explicitly set by the handler (for
    example login replacing it or logout clearing it) wins over a queued roll.
    Without sliding sessions the middleware is inert.
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        sink = _CookieSink()
        scope.setdefault("state", {})[_COOKIE_SINK_STATE_KEY] = sink

        async def send_with_rolled_cookies(message: Message) -> None:
            if message["type"] == "http.response.start":
                sink.apply(message)
            await send(message)

        await self.app(scope, receive, send_with_rolled_cookies)
