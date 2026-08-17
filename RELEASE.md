---
release type: patch
---

OAuth token exchanges now preserve recoverable provider errors, such as GitHub's
`bad_verification_code`, so expired authorization codes are returned to the
client instead of being reported as server failures. Expected rejections are
logged at info level, while genuine provider and response failures retain
server-error handling. Token requests now use a configurable 10-second timeout;
timeouts are reported as `temporarily_unavailable` without retrying the one-time
authorization code, so clients can restart the authorization flow safely.
