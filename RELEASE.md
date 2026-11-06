---
release type: minor
---

**Breaking:** linking a provider sign-in to an existing user by email now also
requires that user to have verified the email. Before, with
`account_linking.enabled`, a provider's verified email was enough to add a
sign-in method to whichever account had that address, so someone who registered
another person's address first, for example with a password that was never
confirmed, got that person's Google or GitHub sign-in attached to their own
account. The existing user now counts as verified when their `email_verified` is
`True`, or when one of their sign-in identities carries the same email with
`provider_email_verified=True`. Otherwise the sign-in fails with
`account_not_linked`, as it already did with linking off. Users created by a
provider sign-in keep working; set `email_verified` on users your application
creates once they confirm their address. Django has no such flag, so there only
users that another provider created can be linked automatically.

Other security fixes:

- A sign-in whose provider email is not verified now fails with
  `email_not_verified` whether or not a user with that email exists, instead of
  `account_not_linked` when one does. The earlier error told whoever added
  someone else's unverified address to their provider account that the person
  had an account. `account_not_linked` is still the answer when the provider
  verified the email and linking is off or the existing user is not verified.
- `GET /{provider}/callback` for Apple, whose callback is a POST, answers
  `400 invalid_request` instead of raising. Apple's `user` form field is
  tolerated in any shape.
- An unreachable JWKS endpoint during ID-token validation raises
  `OAuth2Exception("temporarily_unavailable")`, which the callback and
  `sign_in_with_id_token` report as an OAuth error, instead of an `httpx` error
  that surfaced as a server error.
- The `repr` of hook events, token responses and token requests leaves out
  passwords, client secrets, provider tokens, ID tokens, authorization codes and
  PKCE verifiers, so logging an event no longer logs the credentials Cross-Auth
  handles. The attributes are unchanged. Your own `user` and `social_account`
  records on after events are still shown by their own `repr`.
- `SQLModelAccountsStorage.find_user_by_email` raises `account_not_linked` when
  several users share the email, as the Django storage already did, instead of
  returning one of them for a sign-in to link to.
- While a failed JWKS fetch is cooled down, ID-token validation reports
  `temporarily_unavailable` instead of `invalid_token`, and a failed fetch is
  logged as a warning.

Cross-Auth verifies passwords with the `bcrypt` package directly and no longer
depends on `passlib`, which is unmaintained and incompatible with bcrypt 5. The
hashes are the same `$2b$` bcrypt hashes, so nothing needs re-hashing; passwords
longer than 72 bytes keep verifying by their first 72 bytes, as passlib did. A
hash bcrypt cannot read, such as one produced by another algorithm, now fails
verification instead of raising. If your application imported `passlib` only
because Cross-Auth did, add it to your own dependencies or hash with `bcrypt`.
The `bcrypt<5` pin is gone. Hashes with the original `$2$` prefix, which passlib
accepted and current bcrypt does not, no longer verify; passlib never produced
them, so only hashes imported from a pre-2011 system are affected.
