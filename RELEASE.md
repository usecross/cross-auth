Release type: minor

`get_current_user`, `require_current_user`, and `get_current_session` now take
only the request, so one API serves FastAPI dependencies and direct calls
(shared-context builders, GraphQL resolvers, template helpers) alike. Rolling
the sliding-session cookie moved out of the read path into the new
`SessionCookieMiddleware`: reads that refresh a session queue the rolled cookie
on the request state, and the middleware delivers it on whatever response the
handler produces — including responses returned directly (redirects, streaming,
server-rendered pages), which the previous dependency-injected `Response`
mechanism silently could not reach. If a session refreshes without the
middleware installed, Cross-Auth warns instead of letting the browser cookie
lapse silently.

**Upgrade note:** drop the `response` argument from `get_current_user`,
`require_current_user`, and `get_current_session` calls, and if you configure
`update_age`, add `app.add_middleware(SessionCookieMiddleware)`. `login()` and
`logout()` are unchanged. Without `update_age` the middleware is unnecessary.

The storage record protocols (`SocialAccount`, `User`, `SessionRecord`) now
declare their data members as read-only properties, so concrete models satisfy
them structurally under precise type checkers like `ty`: attributes were checked
invariantly, which rejected models that narrow a field (e.g. a non-nullable
`provider_email_verified`) — including the built-in SQLModel adapters
themselves. Core only ever reads these members, so nothing changes at runtime.
`User.email` is now typed `str | None` to match reality (apps may hold users
without an email; core never reads it — lookups go through
`find_user_by_email`), and the `SocialAccount` protocol is now exported from
`cross_auth`.
