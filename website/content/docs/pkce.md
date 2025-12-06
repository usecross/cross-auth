---
title: PKCE Support
description: Understanding PKCE in Cross Auth
section: Core Concepts
order: 3
---

# PKCE Support

PKCE (Proof Key for Code Exchange) is an extension to the OAuth 2.0 authorization code flow that prevents authorization code interception attacks.

## What is PKCE?

PKCE adds security by using dynamically created secrets instead of static client secrets. It's essential for:

- Public clients (SPAs, mobile apps)
- Preventing authorization code interception
- Secure authentication without storing client secrets in the client

## Automatic PKCE Handling

Cross Auth implements PKCE at two levels:

### 1. Provider-Level PKCE

When communicating with OAuth providers (GitHub, Discord), Cross Auth automatically uses PKCE if the provider supports it:

```python
from cross_auth.social_providers.github import GitHubProvider

github = GitHubProvider(
    client_id="your-client-id",
    client_secret="your-client-secret",
)
# PKCE is automatically used (supports_pkce = True)
```

### 2. Client-Level PKCE

Your client application **must** also use PKCE when communicating with Cross Auth. This is enforced - all authorization requests require a `code_challenge`:

```typescript
// In your client application
const codeVerifier = generateCodeVerifier();
const codeChallenge = await generateCodeChallenge(codeVerifier);

// Start OAuth flow
window.location.href = `https://your-app.com/auth/github/authorize?` +
  `response_type=code&` +
  `redirect_uri=${redirectUri}&` +
  `code_challenge=${codeChallenge}&` +
  `code_challenge_method=S256`;
```

## The PKCE Flow

1. **Client generates code verifier**: Random cryptographic string
2. **Client creates code challenge**: SHA-256 hash of the verifier
3. **Authorization request**: Challenge is sent to Cross Auth
4. **Cross Auth generates its own PKCE**: For the provider OAuth flow
5. **Token exchange**: Client proves possession of the original verifier

## Code Challenge Methods

Cross Auth requires `S256` (SHA-256) code challenge method for security. Plain text challenges are not supported.
