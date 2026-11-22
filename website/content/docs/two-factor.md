---
title: Two-Factor Authentication
description:
  Ask for a code from an authenticator app at sign-in, with single-use recovery
  codes.
order: 5
section: Guides
---

## Overview

Cross-Auth's two-factor authentication (2FA) supports authenticator apps (TOTP,
RFC 6238: 6 digits, 30 seconds, SHA-1) and single-use recovery codes. It is off
until you configure it.

When a user has an authenticator, every sign-in issues nothing until they enter
a code: your password logins, the `/token` password grant, OAuth callbacks
(session and token flows) and `sign_in_with_id_token`. Between the two steps
there is no session, only a short-lived _challenge_ in your secondary storage.

For Django, see
[Two-factor authentication on Django](/docs/django#two-factor-authentication).

## Setup

```python
import os

from sqlalchemy import JSON, Column
from sqlmodel import Field

from cross_auth.fastapi import CrossAuth
from cross_auth.storage.sqlmodel import (
    SQLModelMFAFactor,
    SQLModelMFAStorage,
    SQLModelRecoveryCode,
)


class MFAFactor(SQLModelMFAFactor, table=True):
    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", index=True)
    data: dict = Field(default_factory=dict, sa_column=Column(JSON))


class RecoveryCode(SQLModelRecoveryCode, table=True):
    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", index=True)


auth = CrossAuth(
    ...,
    session_storage=session_storage,  # required with 2FA
    config={
        "mfa": {
            "issuer": "Acme",  # the name authenticator apps show
            "verify_url": "/login/2fa",  # your code page, for OAuth sign-ins
            "secret_keys": [os.environ["MFA_KEY"]],
        },
    },
    mfa_storage=SQLModelMFAStorage(
        MFAFactor, RecoveryCode, session_factory=lambda: Session(engine)
    ),
)
```

Any storage implementing the `MFAStorage` protocol works; the SQLModel one is
built in.

| Key                        | Default         | Meaning                                                                                                      |
| -------------------------- | --------------- | ------------------------------------------------------------------------------------------------------------ |
| `issuer`                   | required        | Name shown in authenticator apps.                                                                            |
| `verify_url`               | none            | Your page where a browser enters its code. OAuth callbacks redirect there.                                   |
| `secret_keys`              | —               | Keys that encrypt TOTP secrets (AES-GCM). The first encrypts, all decrypt: add a new key first to rotate.    |
| `encrypt`, `decrypt`       | —               | Your own functions instead of `secret_keys`, such as a KMS. `decrypt` returns `None` when it cannot decrypt. |
| `require_for_providers`    | `True`          | Whether provider sign-ins (Google, GitHub, Apple, ...) are challenged too.                                   |
| `allow_unverified_email`   | `False`         | Allow users whose email is unverified to turn on 2FA.                                                        |
| `challenge_ttl`            | `300`           | Seconds a sign-in may wait for its code.                                                                     |
| `max_attempts`             | `5`             | Wrong codes one sign-in may try before it must start over.                                                   |
| `lockout_failures`         | `10`            | Wrong codes, across sign-ins, that lock the user's 2FA...                                                    |
| `lockout_seconds`          | `900`           | ...for this long.                                                                                            |
| `reauthentication_max_age` | `300`           | Seconds after a sign-in or `reauthenticate` during which 2FA settings may change.                            |
| `totp_tolerance`           | `1`             | Time steps accepted either side of now.                                                                      |
| `challenge_cookie`         | `mfa_challenge` | Cookie that carries a browser's challenge. HttpOnly.                                                         |

### Which sign-ins are challenged

By default, every sign-in of a user who has a factor. With
`require_for_providers=False`, provider sign-ins are not, and passwords still
are. For any other rule pass `requires_mfa`, which then decides alone:

```python
def requires_mfa(user, login_method: str | None) -> bool:
    # Trust Google's 2FA; challenge everything else.
    return login_method != "google" and auth.get_mfa_status_for(user.id).enabled


auth = CrossAuth(..., requires_mfa=requires_mfa)
```

Returning `True` for a user without a factor refuses the sign-in with
`mfa_enrollment_required` (403), which is how you require 2FA for everyone.

## Turning 2FA on and off

All of these act on the request's signed-in user. Enrolling, regenerating codes
and removing a factor need a recent sign-in (`reauthentication_max_age`);
otherwise they raise `reauthentication_required` (403) with the `methods` the
user can confirm their identity with.

```python
auth.get_mfa_status(request)  # MFAStatus(enabled, factors, recovery_codes_remaining)
auth.reauthenticate(request, password=...)  # or code=..., or recovery_code=...
enrollment = auth.start_totp_enrollment(request, name="iPhone")
# Render enrollment.otpauth_uri as a QR code yourself; show enrollment.secret too.
confirmed = auth.confirm_totp_enrollment(
    request, enrollment_id=enrollment.enrollment_id, code="492039"
)
confirmed.recovery_codes  # 10 codes, shown once; None if the user had some
auth.regenerate_recovery_codes(request)
auth.remove_mfa_factor(request, factor_id)  # the last one turns 2FA off
```

Confirming the first factor revokes the user's other sessions by default
(`revoke_other_sessions=False` keeps them). Enrolling needs a verified email
(`email_not_verified`).

The router mounts the same operations as JSON routes:

| Route                                  | Body                                                    | Answer                                                         |
| -------------------------------------- | ------------------------------------------------------- | -------------------------------------------------------------- |
| `GET /mfa`                             | —                                                       | `{"enabled", "factors", "recovery_codes_remaining"}`           |
| `POST /reauthenticate`                 | `{"password"}`, `{"code"}` or `{"recovery_code"}`       | `{"authenticated_at", "expires_at"}`                           |
| `POST /mfa/totp/enroll`                | `{"name"}` (optional)                                   | `{"enrollment_id", "secret", "otpauth_uri", "expires_at"}`     |
| `POST /mfa/totp/confirm`               | `{"enrollment_id", "code"}`                             | 201 `{"factor", "recovery_codes"}`                             |
| `POST /mfa/recovery-codes`             | —                                                       | `{"recovery_codes"}`                                           |
| `POST /mfa/factors/{factor_id}/remove` | —                                                       | the new status                                                 |
| `POST /mfa/verify`                     | `{"code"}` or `{"recovery_code"}`, optional `challenge` | sign-in finished: 303 to `next`, or `{"redirect_to"}` for JSON |

As with the other routes, CSRF protection for cookie sessions is your job.

## Signing in

### Your password login

`auth.login()` raises `MFARequired` instead of setting a cookie. Show your code
form and finish with `complete_mfa_login`:

```python
from cross_auth.exceptions import CrossAuthException, MFARequired


@app.post("/login")
def login(request: Request, response: Response, form: LoginForm):
    user = auth.authenticate(form.email, form.password)
    if user is None:
        raise HTTPException(400)
    try:
        auth.login(user.id, response=response, login_method="password")
    except MFARequired as required:
        return {
            "mfa_required": True,
            "challenge": required.challenge,
            "methods": required.methods,
        }
    return {"ok": True}


@app.post("/login/2fa")
def login_2fa(request: Request, response: Response, form: CodeForm):
    try:
        auth.complete_mfa_login(
            request, form.challenge, response=response, code=form.code
        )
    except CrossAuthException as error:
        return JSONResponse({"error": error.error}, status_code=error.status_code)
    return {"ok": True}
```

Pass exactly one of `code` and `recovery_code`. A wrong code costs one of the
challenge's attempts.

### Bearer tokens

`issue_session_token()` and `sign_in_with_id_token()` raise `MFARequired` too.
Finish with `auth.verify_mfa(challenge, code=...)`, which returns the token and
its session record.

### OAuth callbacks

A provider sign-in that needs a code sets the HttpOnly challenge cookie and
redirects to `verify_url`. Your page posts the code to `POST /mfa/verify`, which
sets the session cookie and redirects to the sign-in's `next` URL. For an OAuth
client's sign-in, the authorization code is created only after the code checks
out, so `/token` is unchanged.

### The password grant

`/token` with `grant_type=password` answers
`403 {"error": "mfa_required", "mfa_token": ..., "methods": [...]}`. Finish with
`grant_type=urn:cross-auth:grant-type:mfa`, `client_id`, `mfa_token` and `otp`
(or `recovery_code`).

## Hooks

- `mfa.challenge` (after): a sign-in started waiting for a code.
- `mfa.verify` (after): every code check, with `purpose`, `method`, `success`,
  `reason` and, for recovery codes, `recovery_codes_remaining`.
- `mfa.factor.create` and `mfa.factor.delete` (before can refuse; after).
- `mfa.recovery_codes.regenerate` (after).
- `AfterLoginEvent.mfa_method` and `SessionRecord.mfa_method` say which second
  factor a sign-in passed, or `None`.

## Security notes

- Recovery codes are stored as SHA-256 hashes and work once. They can be shown
  only when created.
- A TOTP code is never accepted twice: the last accepted time step is stored.
- 2FA is checked only after the password matched, so it never reveals whether an
  account has 2FA.
- Rate-limit `/mfa/verify`, `/reauthenticate` and your own code routes as you
  would your login route; the lockout is a backstop.
