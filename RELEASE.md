Release type: minor

New `CrossAuth.issue_session_token(user_id, *, max_age=None, metadata=None)`
mints a revocable opaque bearer token programmatically — for clients that
authenticate outside the built-in `/token` endpoint and outside a browser, such
as a GraphQL sign-in mutation for a native app or a CLI. It returns the raw
token together with the created session record, honors a per-call `max_age`
(e.g. longer-lived mobile sessions than browser cookies), stores the usual
session metadata, and the token resolves through `get_current_user` and revokes
through the existing session-management APIs. No cookie is set, and the new
`session.issue` before/after hooks run around the creation — so programmatic
issuance goes through the same policy and audit surface as cookie logins and
`/token` grants (block suspended users, clamp requested lifetimes, audit issued
sessions). The raw token is never exposed to hooks.
