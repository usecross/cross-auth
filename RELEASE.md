---
release type: minor
---

**Breaking:** linking a sign-in to an existing user by email now requires the
provider to report the email as verified. Before, `GitHubProvider`,
`DiscordProvider` and providers built on `OAuth2Provider` or `OIDCProvider`
(including `AppleProvider`) defaulted to `trust_email=True`. With
`account_linking.enabled`, a provider identity whose email the provider reported
as unverified was added as a login method to the user with that email, even with
`require_verified_email`, which only applies to new users.

- Every provider now defaults to `trust_email=False`, like `GoogleProvider`. A
  sign-in whose email matches an existing user links only when the provider
  reports `email_verified=True`. Otherwise it fails with `account_not_linked`:
  nothing is attached and nobody is signed in.
- `trust_email=True` now only accepts an email the provider sends without a
  verification claim. An email the provider reports as unverified never links,
  and `finalize-link` or a connect that enables login rejects it with
  `email_not_verified`.
- `OAuth2Provider.trusts_email(email_verified)` applies this rule.

Identities that are already linked keep signing in by provider user ID. If a
custom provider verifies email ownership but never reports it, opt back in:

```python
class CustomProvider(OAuth2Provider):
    def __init__(self, client_id: str, client_secret: str):
        super().__init__(client_id, client_secret, trust_email=True)
```

Token exchange failures no longer log provider credentials. Cross Auth logged
the token endpoint's response body on HTTP errors, and the Pydantic validation
error, input included, when it could not parse a response, so access, refresh
and ID tokens could reach your logs. It now logs the HTTP status and OAuth
`error` code, or the failing fields and error types:

```text
HTTP error during token exchange (status=400, error=invalid_grant)
Failed to parse token response (TokenResponse.token_type=missing, TokenErrorResponse.error=missing)
```

The records carry `oauth_provider` in `extra`, and HTTP errors also carry
`oauth_status_code` and `oauth_error`. The `OAuth2Exception` that
`exchange_code()` raises no longer chains the validation or HTTP error.
