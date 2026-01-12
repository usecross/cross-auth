---
release type: minor
---

This release adds support for `client_id` validation, which is now required when calling `/authorize`.

**Before:**
```
GET /github/authorize?redirect_uri=...&response_type=code&code_challenge=...&code_challenge_method=S256
```

**After:**
```
GET /github/authorize?client_id=my_app&redirect_uri=...&response_type=code&code_challenge=...&code_challenge_method=S256
```

The same `client_id` must be sent in the token exchange request.
