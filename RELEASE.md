---
release type: minor
---

Use one `login` hook lifecycle for every login that issues a credential. Browser
and `CrossAuth.login` cookie logins, `issue_session_token`, and the `/token`
password and authorization-code grants (including credentials minted by a custom
`token_issuer`) now each run exactly one `before("login")` / `after("login")`
pair. The `session.issue` hooks and their event types are removed.

Both login events gain `credential` (`"cookie"` or `"bearer"`), and
`BeforeLoginEvent` gains `max_age` and `metadata`. `response` is set only for
cookie logins, `session_record` is `None` for `token_issuer` credentials, and
`AfterLoginEvent.cookie` is removed. Existing login hooks also run for bearer
logins; check `event.response is not None` before accessing its fields. Login
before hooks can deny a login or adjust its lifetime, metadata, and cookie
response, but changing `user_id` now raises `ValueError` instead of logging in a
different user.

Exceptions raised by after hooks, including `CrossAuthException`, now propagate
instead of being logged and ignored. Work that already completed, such as a
saved session, is not undone.
