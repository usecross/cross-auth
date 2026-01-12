---
release type: minor
---

Added `POST /{provider}/link` endpoint for initiating account link flows.

This is the recommended way to start linking a social account. It accepts a JSON body with the OAuth parameters and returns the provider's authorization URL. Authentication happens via the standard `Authorization` header, so tokens never appear in URLs.

### Usage

```javascript
// POST /api/v1/github/link
const response = await fetch("/api/v1/github/link", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    Authorization: `Bearer ${accessToken}`,
  },
  body: JSON.stringify({
    redirect_uri: "https://example.com/callback",
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    client_id: "my_app",
  }),
})

const { authorization_url } = await response.json()
window.location.href = authorization_url
```

### Breaking Change

The `response_type=link_code` parameter on the `GET /{provider}/authorize` endpoint is no longer supported. Use the new `POST /{provider}/link` endpoint instead.
