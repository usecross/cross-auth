---
title: Security Integration
description:
  Protect authentication routes with application CSRF checks and rate limits.
order: 7
section: Guides
---

## What the application must provide

Cross-Auth does not install general CSRF protection or rate limiting. Apply both
at your application's HTTP boundary, including routes you write around
`authenticate()`, `sign_in_with_id_token()`, `login()`, `logout()`, and session
revocation. `SessionCookieMiddleware` only delivers refreshed session cookies.

Browser OAuth callbacks have their own protection: expiring, single-use state,
an initiating-browser binding cookie, provider binding, PKCE where supported,
and a managed nonce for OIDC. These checks do not authorize unrelated browser
requests. `trusted_origins` does not configure CSRF or CORS. The
`client_redirect_uris` configuration or `get_client` callback registers OAuth
client callbacks; it does not grant permission to make cookie-authenticated
requests.

Route paths below are relative to where you include `auth.router`:

| Route                                                         | Application protection                                                                                                                                                         |
| ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `GET /{provider}/connect`                                     | Check browser origin or a CSRF token before starting an account connection, even though this route uses GET.                                                                   |
| `POST /{provider}/link`, `POST /{provider}/finalize-link`     | Require CSRF protection when browser cookies can authenticate the request.                                                                                                     |
| `DELETE /{provider}/social-accounts[/id]`                     | Require CSRF protection and retain Cross-Auth's ownership checks.                                                                                                              |
| `GET` or `POST /{provider}/callback`                          | Keep Cross-Auth's OAuth checks. Exempt these exact routes from ordinary form-CSRF checks so provider callbacks work. Rate-limit them.                                          |
| `GET /{provider}/login`, `GET /{provider}/authorize`          | Rate-limit authorization starts and temporary-state allocation.                                                                                                                |
| `POST /token`                                                 | Rate-limit credential verification and token issuance. This endpoint returns a bearer token; it does not authenticate through the browser's session cookie or set that cookie. |
| Your password/native login, logout, session-revocation routes | Apply CSRF checks to browser endpoints, including login before a user has a session. Use POST or DELETE for mutations. Apply rate limits before calling Cross-Auth.            |

## Protect browser requests in FastAPI

Use your application's CSRF middleware or dependency. If it uses CSRF tokens,
validate a session-bound token from a header or form field before the mutation.
Keep tokens out of URLs. `SameSite` and CORS alone do not cover all browser
request patterns. See
[OWASP's CSRF guidance](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).

The following dependency implements a strict Origin/Referer policy for a browser
application. It rejects missing and `null` origins instead of allowing an
unverified request. Set exact public origins, including scheme and any
nondefault port; do not derive the allowlist from the request's Host or
forwarded headers.

```python
from urllib.parse import urlsplit

from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse

BROWSER_ORIGINS = {"https://app.example.com"}


def require_browser_origin(request: Request) -> None:
    origin = request.headers.get("origin")

    if origin is None:
        try:
            referer = urlsplit(request.headers.get("referer", ""))
            origin = f"{referer.scheme}://{referer.netloc}"
        except ValueError:
            origin = None

    if origin not in BROWSER_ORIGINS:
        raise HTTPException(403, "Untrusted browser request")


# Use the same provider list passed to CrossAuth(providers=providers, ...).
callback_posts = {f"{provider.id}_callback_post" for provider in providers}
connect_starts = {f"{provider.id}_connect" for provider in providers}


def protect_auth_browser_requests(request: Request) -> None:
    operation = request.scope["route"].operation_id

    if operation in callback_posts or operation == "token":
        return

    if request.method in {"GET", "HEAD", "OPTIONS"}:
        if operation not in connect_starts:
            return

    require_browser_origin(request)


app.include_router(
    auth.router,
    prefix="/auth",
    dependencies=[Depends(protect_auth_browser_requests)],
)


@app.post("/logout", dependencies=[Depends(require_browser_origin)])
def logout(request: Request):
    response = JSONResponse({"ok": True})
    auth.logout(request, response=response)
    return response
```

Attach `require_browser_origin` to your browser login and session-management
routes too. FastAPI supports these dependencies when
[including a router](https://fastapi.tiangolo.com/tutorial/bigger-applications/#include-an-apirouter-with-a-custom-prefix-tags-responses-and-dependencies).
The operation IDs above are those supplied by Cross-Auth; adjust the dispatch if
you customize them. Register each router only once, with its protections.

This policy requires an allowed Origin or Referer even for direct navigation to
`/connect`. A browser with both headers suppressed will be rejected; use your
application's CSRF-token mechanism if you need to support that case. Exempt only
the provider callback routes from an outer CSRF middleware, not all of `/auth`.
Apple's cross-site form POST must reach the callback handler; Cross-Auth then
redirects to a GET continuation to verify the initiating browser's binding.

A bearer-only API can use a different policy if it never accepts ambient browser
credentials. Do not bypass CSRF checks just because an Authorization header is
present: Cross-Auth's default resolver prefers a valid session cookie over a
bearer token. Keep cookie-authenticated and bearer-only entry points explicit.

## Apply limits before expensive work

Place request limits in your gateway, ASGI middleware, or FastAPI dependencies.
Cover authorization starts, callbacks, `/token`, account changes, and your own
credential endpoints. Middleware or a gateway can also enforce body-size limits
before FastAPI parses the request body.

Use shared atomic counters across workers. An in-process dictionary and
`SecondaryStorage.get()` followed by `set()` do not provide that guarantee. For
example, an application with Redis can use a small
[atomic counter script](https://redis.io/docs/latest/commands/incr/):

```python
import os

from redis import Redis
from redis.exceptions import RedisError

limit_store = Redis.from_url(
    os.environ["AUTH_RATE_LIMIT_REDIS_URL"],
    socket_connect_timeout=1,
    socket_timeout=1,
)
count_attempt = limit_store.register_script("""
local count = redis.call('INCR', KEYS[1])
if count == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return count
""")


def limit_auth_requests(request: Request) -> None:
    # Configure your server to trust forwarded addresses only from your proxy.
    address = request.client.host if request.client else "unknown"
    operation = request.scope["route"].operation_id

    try:
        count = count_attempt(
            keys=[f"auth-limit:ip:{operation}:{address}"],
            args=[60],
        )
    except RedisError as exc:
        raise HTTPException(503, "Authentication temporarily unavailable") from exc

    if int(count) > 60:
        raise HTTPException(429, "Too many requests", headers={"Retry-After": "60"})
```

Add `Depends(limit_auth_requests)` to the same `include_router` dependencies
list, and to your own login routes. This is a starting point for a
per-operation, per-IP budget, not a complete credential-attack policy. Tune the
example's 60-attempt/60-second limit for your traffic, including shared networks
and callback retries. The example denies requests when the limiter is
unavailable; make the outage policy explicit in your deployment.

Add an account/normalized-identifier budget to password verification so changing
IP addresses does not reset every limit. Count attempts before verification,
including unknown accounts, with the same external error behavior. Bound the
window and avoid permanent lockouts an attacker could trigger against another
user. See
[OWASP's login-throttling guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#login-throttling).

### Where hooks fit

`before("authenticate")` can enforce an account-level budget before password
verification, using the event's email and your application's shared limiter. It
has no request or source IP. The legacy `/token` password grant calls
`before("token.password")`, not `before("authenticate")`; protect both if that
grant is exposed. `before("oauth.id_token")` runs before ID-token validation but
has only the provider name, raw token, and supplied user metadata. Those inputs
do not establish a trusted user identity, and the hook has no request or source
IP. Apply the request limit outside these hooks.

Before hooks can reject with `CrossAuthException`; after hooks run too late to
block the operation. `/token` converts hook errors into HTTP 400 OAuth errors,
so use the HTTP dependency or middleware for a real HTTP 429 and `Retry-After`.
Your own routes must handle `CrossAuthException` from direct method calls.

## Cookie and deployment settings

Session cookies default to Secure, HttpOnly, SameSite=Lax, path `/`, and no
Domain attribute. Keep HTTPS in production and prefer a host-only cookie.
Changing to SameSite=None for a cross-site frontend requires Secure cookies and
explicit CSRF and credentialed-CORS configuration. Do not log session tokens,
authorization codes, passwords, or raw ID tokens when monitoring rejected
requests.

For another framework, enforce the same checks in its middleware/views before
calling Cross-Auth. Reuse its CSRF system where available; authentication and
session helpers do not replace it.
