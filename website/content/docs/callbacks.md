---
title: OAuth Flow & Callbacks
description: Understanding the OAuth flow in Cross Auth
section: Advanced
order: 1
---

# OAuth Flow & Callbacks

Cross Auth implements a complete OAuth 2.0 authorization code flow with PKCE.

## OAuth Endpoints

When you add the AuthRouter, these endpoints are automatically created for each provider:

- `/{provider}/authorize` - Start the OAuth flow
- `/{provider}/callback` - Handle provider redirect
- `/{provider}/finalize-link` - Finalize account linking

For example, with GitHub:
- `/auth/github/authorize`
- `/auth/github/callback`
- `/auth/github/finalize-link`

## The Complete Flow

### 1. Authorization Request

Client initiates OAuth flow with PKCE:

```
GET /auth/github/authorize
  ?response_type=code
  &redirect_uri=https://your-app.com/callback
  &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
  &code_challenge_method=S256
  &state=client_state_for_csrf
```

### 2. Provider Authorization

Cross Auth redirects to GitHub with its own PKCE parameters.

### 3. Provider Callback

GitHub redirects back to `/auth/github/callback` with an authorization code.

### 4. User Creation/Login

Cross Auth:
1. Exchanges code for access token (with PKCE verification)
2. Fetches user info from GitHub
3. Creates or updates user and social account in your database
4. Generates an authorization code for your client

### 5. Client Redirect

User is redirected back to your app with the authorization code:

```
https://your-app.com/callback?code=abc123&state=client_state_for_csrf
```

### 6. Token Exchange

Your client exchanges the code for tokens:

```
POST /auth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=abc123
&redirect_uri=https://your-app.com/callback
&client_id=your-client-id
&code_verifier=original_verifier
```

## Account Linking Flow

To link additional providers to an existing account, use `response_type=link_code`:

```
GET /auth/discord/authorize
  ?response_type=link_code
  &redirect_uri=https://your-app.com/settings
  &code_challenge=...
  &code_challenge_method=S256
```

The user must be authenticated. After provider authorization, finalize the link:

```
POST /auth/discord/finalize-link
Content-Type: application/json

{
  "link_code": "xyz789",
  "code_verifier": "original_verifier"
}
```
