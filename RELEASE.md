---
release type: minor
---

Two-factor authentication: authenticator apps (TOTP) and single-use recovery
codes, for FastAPI, SQLModel storage and Django. It is off until you configure
`config["mfa"]` with an `mfa_storage` (or `CROSS_AUTH["MFA"]` on Django).

When a user has an authenticator, no sign-in issues a credential until they
enter a code: password logins, the password grant, OAuth callbacks and
`sign_in_with_id_token`. Provider sign-ins are challenged too unless you set
`require_for_providers` to `False`; `requires_mfa` replaces the rule. The
default rule does not challenge device logins (`login_method="device"`), which a
user approves from a browser where they are already signed in. Their sessions
never count as a recent sign-in: they must `reauthenticate` before they enroll,
regenerate recovery codes or remove a factor.

- `CrossAuth` gains `start_totp_enrollment`, `confirm_totp_enrollment`,
  `regenerate_recovery_codes`, `remove_mfa_factor`, `reauthenticate`,
  `get_mfa_status`, `complete_mfa_login` and `verify_mfa`; the router mounts
  `/mfa`, `/mfa/totp/enroll`, `/mfa/totp/confirm`, `/mfa/recovery-codes`,
  `/mfa/factors/{id}/remove`, `/mfa/verify` and `/reauthenticate`.
- With 2FA on, `login()`, `issue_session_token()` and `sign_in_with_id_token()`
  raise `MFARequired` for a user who needs a code.
- `challenge_ttl` is at most 3600 seconds, `reauthentication_max_age` at most
  86400 and `lockout_seconds` at most 30 days; a larger value raises
  `ValueError`.
- Once the code checks out, every sign-in asks `user_can_authenticate` again, so
  a user refused while their sign-in waited is refused then, with the refusal
  the rule returns or raises.
- `reauthenticate(password=...)` checks the password with `CrossAuth`'s
  `password_hasher`, as sign-in does; Django checks it with `check_password()`.
- Revoking a user's sessions also ends their sign-ins that are waiting for a
  code, which then answer `invalid_challenge`: `change_password()`,
  `revoke_all_sessions()`, `revoke_other_sessions()`,
  `POST /sessions/revoke-others`, `POST /logout` with `{"scope": "all"}`, and
  Django's `revoke_other_sessions()`. Revoking one session does not.
- SQLModel: `SQLModelMFAFactor`, `SQLModelRecoveryCode` and
  `SQLModelMFAStorage`, whose factor table's `user_id` must be a foreign key to
  your user table; `SQLModelSession` gains `mfa_method`. Before you deploy, add
  the nullable `mfa_method` column to every existing session table, even with
  MFA off: session reads select it.
- Django: migration `0005_mfa` (run `migrate`), `cross_auth.django.mfa` with
  `MFAMiddleware`, the verify page (or your own, with `MFA["verify_url"]` and
  `get_pending_mfa`) and the JSON views, new signals, checks `E006` and `E008`,
  and `cross_auth.django.test.login_with_mfa`. With MFA on,
  `cross_auth.django.sessions` is required and Django's `update_last_login`
  waits for the second factor. `W001` now only warns about other MFA apps.
- `BrowserLogin.login`, `SessionStorage.create`, `BeforeLoginEvent` and
  `AfterLoginEvent` gain `mfa_method`. Custom session storages need the new
  argument only when 2FA is on.
- `TokenIssueRequest` gains `mfa_method`, the second factor the sign-in passed,
  and `issue_session_token()` takes it: a `token_issuer` that issues sessions
  with `issue_session_token()` passes `mfa_method=request.mfa_method`, so a
  sign-in that entered its code is not asked again.
- `AfterTokenPasswordEvent` replaces `request` with `scope`, so the event no
  longer carries the password; it now also runs for password grants finished
  through 2FA.
- Custom `MFAStorage` implementations: `create_factor` takes
  `recovery_code_hashes` and returns `(factor, first)`, `delete_factor` returns
  how many factors are left (`None` if none was deleted) and removes the
  recovery codes with the last one, and `replace_recovery_codes` returns `False`
  without a factor. Each runs under a per-user lock, as do `record_failure`,
  `lock` and `reset_failures`. The new `on_commit` delivers the 2FA after hooks
  once the change is committed.
- With the password grant on, the `/token` schema documents the MFA grant and
  its 403 and 429 answers. The MFA grant is refused once `password_grant` is
  off.
