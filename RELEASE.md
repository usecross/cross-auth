---
release type: minor
---

Two-factor authentication: authenticator apps (TOTP) and single-use recovery
codes, for FastAPI, SQLModel storage and Django. It is off until you configure
`config["mfa"]` with an `mfa_storage` (or `CROSS_AUTH["MFA"]` on Django).

When a user has an authenticator, no sign-in issues a credential until they
enter a code: password logins, the password grant, OAuth callbacks and
`sign_in_with_id_token`. Provider sign-ins are challenged too unless you set
`require_for_providers` to `False`; `requires_mfa` replaces the rule.

- `CrossAuth` gains `start_totp_enrollment`, `confirm_totp_enrollment`,
  `regenerate_recovery_codes`, `remove_mfa_factor`, `reauthenticate`,
  `get_mfa_status`, `complete_mfa_login` and `verify_mfa`; the router mounts
  `/mfa`, `/mfa/totp/enroll`, `/mfa/totp/confirm`, `/mfa/recovery-codes`,
  `/mfa/factors/{id}/remove`, `/mfa/verify` and `/reauthenticate`.
- With 2FA on, `login()`, `issue_session_token()` and `sign_in_with_id_token()`
  raise `MFARequired` for a user who needs a code.
- SQLModel: `SQLModelMFAFactor`, `SQLModelRecoveryCode` and
  `SQLModelMFAStorage`; `SQLModelSession` gains `mfa_method`. Add the column.
- Django: migration `0005_mfa` (run `migrate`), `cross_auth.django.mfa` with
  `MFAMiddleware`, the verify page (or your own, with `MFA["verify_url"]` and
  `get_pending_mfa`) and the JSON views, new signals, checks `E006` and `E008`,
  and `cross_auth.django.test.login_with_mfa`. With MFA on,
  `cross_auth.django.sessions` is required and Django's `update_last_login`
  waits for the second factor. `W001` now only warns about other MFA apps.
- `BrowserLogin.login`, `SessionStorage.create`, `BeforeLoginEvent` and
  `AfterLoginEvent` gain `mfa_method`. Custom session storages need the new
  argument only when 2FA is on.
