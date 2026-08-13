---
release type: minor
---

OAuth callback errors that occur when the stored auth request is missing or
expired no longer return a bare JSON 400. The callback endpoint is a top-level
browser navigation, so those responses stranded real users — anyone who idled
past the state's 10-minute TTL on a provider's consent screen, resumed an
abandoned tab, or refreshed the single-use callback URL — on a JSON document on
the API origin with no way back to the app.

These dead-ends now redirect (302) to `default_next_url` — the same
operator-configured fallback the success paths already use — with the error in
the query string:

- an unknown or expired `state` redirects with `error=session_expired`,
- a callback carrying no `state` at all redirects with `error=invalid_request`,
- a provider-reported error arriving with an unknown `state` passes the
  provider's own error code through.

Each redirect also carries a human-readable `error_description`. Apps can match
on `error=session_expired` to show a "your session expired, please try again"
message. Callbacks whose auth request is still available are handled exactly as
before.
