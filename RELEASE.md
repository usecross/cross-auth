---
release type: minor
---

This release adds Apple Sign In support via a new OIDC base provider.

Key changes:

- Added `OIDCProvider` base class for OpenID Connect providers, with JWT
  id_token validation against provider JWKS endpoints and automatic key rotation
  handling.
- Added `AppleProvider` for Apple Sign In, supporting ES256 JWT client secret
  generation, `form_post` response mode, and Apple-specific id_token parsing.
- `AppleProvider` now accepts individual constructor args (`client_id`,
  `team_id`, `key_id`, `private_key`) instead of a config object, matching the
  pattern used by other providers.
- Made `client_secret` optional in `OAuth2Provider` for providers like Apple
  that generate it dynamically.
- Renamed `fetch_user_info`/`get_user_info_from_token_response` to
  `get_user_info` for consistency across providers.
