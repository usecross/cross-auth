---
release type: minor
---

OAuth client redirects now require per-client registration through
`config["client_redirect_uris"]` or a `get_client(client_id)` callback returning
an `OAuthClient`. This supports hardcoded and database-backed applications with
shared redirect validation. Replace `allowed_client_ids` with a registration
source; the old setting raises a migration error at startup. `trusted_origins`
no longer authorizes client redirects. Without registrations, `/authorize` and
`/link` reject clients; session login and connection flows remain available.

Redirects are checked before sending errors to a client and checked again when
completing pending callbacks or redeeming codes. Matching preserves the original
URL string, including scheme, port, path, and query. Native `OAuthClient`
registrations also support exact reverse-domain private-use URI schemes and HTTP
loopback redirects on `127.0.0.1` or `[::1]`, where only the port may vary.
Client lookup results are not cached; applications can remove or disable
registrations without restarting Cross-Auth. Existing sessions are not revoked
by client removal. Registrations use ASCII URI spelling, with non-ASCII paths
percent-encoded and international hostnames in punycode. Pending flows whose
client/callback is no longer registered must restart after the configuration is
updated.

Link redemption rejects malformed request bodies and verifiers without consuming
the code. Expiry is enforced at the deadline and checked again after atomic
consumption, before contacting the provider. Concurrent redemption still allows
only one provider exchange. Non-ASCII PKCE challenges and verifiers return an
authentication error instead of raising encoding/comparison errors.

The security integration guide documents application-owned CSRF protection and
shared rate limits, including FastAPI dependencies and provider-callback
exemptions. Cross-Auth does not install these protections automatically.
