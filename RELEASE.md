---
release type: minor
---

OAuth callbacks now require the browser that started the flow. Each attempt uses
an expiring, single-use state and a separate HttpOnly cookie. Connect callbacks
recheck the signed-in user; link finalization checks the user and provider and
consumes the link code atomically. Apple form-post callbacks continue through a
GET so SameSite=Lax cookies can be checked.

Existing sessions remain valid. In-flight OAuth and link requests from earlier
versions must be restarted. Deploy the initiation, callback, and finalize-link
endpoints together: the new state namespace is intentionally incompatible with
old workers. Browser clients calling the link endpoint across origins must use
`credentials: "include"` and credentialed CORS to accept its binding cookie.
