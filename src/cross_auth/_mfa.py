"""Two-factor authentication: TOTP authenticators and recovery codes.

Every 2FA rule lives here and works on already-resolved users, never on a
framework request, so FastAPI and Django share it. Storages only keep rows
(``MFAStorage``); short-lived state (sign-in challenges and enrollments still
waiting for their first code) lives in ``SecondaryStorage``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, TypedDict

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import AwareDatetime, BaseModel, ValidationError

from . import _totp
from ._storage import AccountsStorage, MFAFactor, MFAStorage, SecondaryStorage, User
from .exceptions import CrossAuthException, MFARequired
from .hooks import (
    AfterMFAChallengeEvent,
    AfterMFAFactorCreateEvent,
    AfterMFAFactorDeleteEvent,
    AfterMFARecoveryCodesRegenerateEvent,
    AfterMFAVerifyEvent,
    BeforeMFAFactorCreateEvent,
    BeforeMFAFactorDeleteEvent,
    HookRegistry,
    MFAVerifyPurpose,
    UserSnapshot,
)


class MFAConfig(TypedDict, total=False):
    """``config["mfa"]``: two-factor authentication settings."""

    # Shown as the account's name in authenticator apps. Required.
    issuer: str
    # The application's page where a browser sign-in enters its code. The
    # OAuth callback redirects there; it posts to ``POST /mfa/verify``.
    verify_url: str
    # Keys that encrypt TOTP secrets with AES-GCM: the first encrypts, every
    # one decrypts, so add a new key first to rotate. Give either these or
    # both ``encrypt`` and ``decrypt``.
    secret_keys: Sequence[str]
    encrypt: Callable[[str], str]
    # Return None when the text cannot be decrypted, e.g. after a key change.
    decrypt: Callable[[str], str | None]
    # Seconds a sign-in may wait for its second factor. Default 300.
    challenge_ttl: int
    # Wrong codes one sign-in may try before it must start over. Default 5.
    max_attempts: int
    # Wrong codes, across sign-ins and factors, that lock a user's 2FA, and
    # for how many seconds. Defaults 10 and 900.
    lockout_failures: int
    lockout_seconds: int
    # Seconds after signing in or reauthenticating during which the user may
    # change their 2FA settings. Default 300.
    reauthentication_max_age: int
    # TOTP time steps accepted either side of now. Default 1.
    totp_tolerance: int
    # Whether provider sign-ins (Google, GitHub, ...) need 2FA. Default True.
    require_for_providers: bool
    # Allow users whose email is unverified to turn on 2FA. Default False.
    allow_unverified_email: bool
    # Name of the cookie a browser sign-in keeps its challenge in.
    challenge_cookie: str


_DEFAULTS: dict[str, Any] = {
    "challenge_ttl": 300,
    "max_attempts": 5,
    "lockout_failures": 10,
    "lockout_seconds": 15 * 60,
    "reauthentication_max_age": 300,
    "totp_tolerance": 1,
    "require_for_providers": True,
    "allow_unverified_email": False,
    "challenge_cookie": "mfa_challenge",
}

# Decides whether this sign-in needs 2FA. Returning True for a user without a
# factor refuses the sign-in until they enroll.
RequiresMFA = Callable[[User, str | None], bool]
PasswordVerifier = Callable[[User, str], bool]
UserPredicate = Callable[[User], bool]

ENROLLMENT_TTL = 600
RECOVERY_CODE_COUNT = 10
# No 0/o, 1/l/i: codes are often typed from paper.
_RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"
_RECOVERY_LENGTH = 10

_CHALLENGE_KEY = "mfa:challenge:{digest}"
_ENROLLMENT_KEY = "mfa:enrollment:{digest}"

# What a challenge finishes: a cookie or bearer session, a password grant's
# token, an OAuth client's authorization code, an OAuth callback's browser
# login, or a login a framework completes itself (Django's guard).
ChallengeKind = Literal[
    "cookie", "bearer", "token", "authorization_code", "browser", "framework"
]


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hash_recovery_code(code: str) -> str:
    normalized = code.replace("-", "").replace(" ", "").strip().lower()
    return _digest(normalized)


def generate_recovery_codes() -> list[str]:
    codes = []
    for _ in range(RECOVERY_CODE_COUNT):
        raw = "".join(
            secrets.choice(_RECOVERY_ALPHABET) for _ in range(_RECOVERY_LENGTH)
        )
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


class _Cipher:
    """Encrypts TOTP secrets with the application's keys."""

    _PREFIX = "v1."

    def __init__(self, config: MFAConfig) -> None:
        encrypt = config.get("encrypt")
        decrypt = config.get("decrypt")
        keys = list(config.get("secret_keys") or [])
        if (encrypt is None) != (decrypt is None):
            raise ValueError("config['mfa'] needs both encrypt and decrypt, or neither")
        if encrypt is not None and keys:
            raise ValueError(
                "config['mfa'] takes secret_keys or encrypt/decrypt, not both"
            )
        if encrypt is None and not keys:
            raise ValueError(
                "config['mfa'] needs secret_keys, or encrypt and decrypt, to "
                "store TOTP secrets"
            )
        if any(not isinstance(key, str) or not key for key in keys):
            raise ValueError("config['mfa']['secret_keys'] must be non-empty strings")
        self._encrypt = encrypt
        self._decrypt = decrypt
        self._keys = [
            AESGCM(hashlib.sha256(f"cross-auth-mfa:{key}".encode()).digest())
            for key in keys
        ]

    def encrypt(self, plaintext: str) -> str:
        if self._encrypt is not None:
            return self._encrypt(plaintext)
        nonce = secrets.token_bytes(12)
        sealed = self._keys[0].encrypt(nonce, plaintext.encode("utf-8"), None)
        return self._PREFIX + base64.urlsafe_b64encode(nonce + sealed).decode()

    def decrypt(self, text: str) -> str | None:
        if self._decrypt is not None:
            return self._decrypt(text)
        if not text.startswith(self._PREFIX):
            return None
        try:
            raw = base64.urlsafe_b64decode(text[len(self._PREFIX) :])
        except ValueError:
            return None
        nonce, sealed = raw[:12], raw[12:]
        for key in self._keys:
            try:
                return key.decrypt(nonce, sealed, None).decode("utf-8")
            except InvalidTag:
                continue
        return None


@dataclass(frozen=True)
class MFAFactorInfo:
    """A factor as the API shows it: never its secret."""

    id: str
    type: str
    name: str | None
    created_at: datetime
    last_used_at: datetime | None

    @classmethod
    def of(cls, factor: MFAFactor) -> MFAFactorInfo:
        last_used_at = factor.last_used_at
        return cls(
            id=str(factor.id),
            type=factor.type,
            name=factor.name,
            created_at=_aware(factor.created_at),
            last_used_at=None if last_used_at is None else _aware(last_used_at),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "name": self.name,
            "created_at": self.created_at.isoformat(),
            "last_used_at": (
                None if self.last_used_at is None else self.last_used_at.isoformat()
            ),
        }


@dataclass(frozen=True)
class MFAStatus:
    # True when the user has at least one factor.
    enabled: bool
    factors: list[MFAFactorInfo]
    recovery_codes_remaining: int

    def to_json(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "factors": [factor.to_json() for factor in self.factors],
            "recovery_codes_remaining": self.recovery_codes_remaining,
        }


@dataclass(frozen=True)
class TotpEnrollment:
    enrollment_id: str
    # Base32, for typing into an authenticator app by hand.
    secret: str
    # otpauth://totp/...: render it as a QR code, locally.
    otpauth_uri: str
    expires_at: datetime

    def to_json(self) -> dict[str, Any]:
        return {
            "enrollment_id": self.enrollment_id,
            "secret": self.secret,
            "otpauth_uri": self.otpauth_uri,
            "expires_at": self.expires_at.isoformat(),
        }


@dataclass(frozen=True)
class TotpConfirmation:
    factor: MFAFactorInfo
    # New codes, shown once: when the user had none, as on their first
    # factor. None when they already have codes.
    recovery_codes: list[str] | None

    @property
    def enabled_mfa(self) -> bool:
        return self.recovery_codes is not None

    def to_json(self) -> dict[str, Any]:
        return {"factor": self.factor.to_json(), "recovery_codes": self.recovery_codes}


class Challenge(BaseModel):
    """A sign-in waiting for its second factor, and how to finish it."""

    user_id: str
    login_method: str | None
    kind: ChallengeKind
    # What finishing needs: the session settings, the client's redirect, or
    # what a framework stored.
    data: dict[str, Any]
    attempts_left: int
    expires_at: AwareDatetime


class _Enrollment(BaseModel):
    user_id: str
    session_id: str
    secret: str
    name: str | None


class ReauthenticationRequired(CrossAuthException):
    """A 2FA change needs the user to prove who they are again."""

    def __init__(self, methods: list[str]) -> None:
        super().__init__(
            "reauthentication_required",
            "Confirm it is you before changing two-factor authentication",
            status_code=403,
        )
        # What the user can reauthenticate with: "password", "totp",
        # "recovery_code", or "sign_in_again" (sign in with a provider).
        self.methods = methods


def _invalid_code() -> CrossAuthException:
    return CrossAuthException("invalid_code", "The code is not correct")


def _default_password_verifier(user: User, password: str) -> bool:
    from ._password import _verify_password

    return _verify_password(user, password)


def resolve_config(config: MFAConfig) -> dict[str, Any]:
    """Check ``config['mfa']`` and fill in its defaults; raise ``ValueError``."""
    unknown = config.keys() - MFAConfig.__optional_keys__
    if unknown:
        raise ValueError(f"Unknown config['mfa'] keys: {', '.join(sorted(unknown))}")
    issuer = config.get("issuer")
    if not isinstance(issuer, str) or not issuer:
        raise ValueError("config['mfa']['issuer'] must be a non-empty string")
    resolved: dict[str, Any] = {**_DEFAULTS, **config}
    for key in (
        "challenge_ttl",
        "max_attempts",
        "lockout_failures",
        "lockout_seconds",
        "reauthentication_max_age",
    ):
        value = resolved[key]
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError(f"config['mfa']['{key}'] must be a positive int")
    tolerance = resolved["totp_tolerance"]
    if (
        not isinstance(tolerance, int)
        or isinstance(tolerance, bool)
        or not 0 <= tolerance <= 10
    ):
        raise ValueError("config['mfa']['totp_tolerance'] must be from 0 to 10")
    for key in ("require_for_providers", "allow_unverified_email"):
        if not isinstance(resolved[key], bool):
            raise ValueError(f"config['mfa']['{key}'] must be a bool")
    _Cipher(config)
    return resolved


class MFA:
    """Cross Auth's 2FA rules, for one context."""

    def __init__(
        self,
        *,
        config: MFAConfig,
        storage: MFAStorage,
        secondary_storage: SecondaryStorage,
        accounts_storage: AccountsStorage,
        hooks: HookRegistry,
        provider_ids: frozenset[str] = frozenset(),
        requires_mfa: RequiresMFA | None = None,
        verify_password: PasswordVerifier | None = None,
        has_password: UserPredicate | None = None,
        email_verified: UserPredicate | None = None,
    ) -> None:
        self.config = resolve_config(config)
        issuer = self.config["issuer"]
        self.issuer = issuer
        self.cipher = _Cipher(config)
        self.storage = storage
        self.secondary_storage = secondary_storage
        self.accounts_storage = accounts_storage
        self.hooks = hooks
        self.provider_ids = provider_ids
        self.requires_mfa = requires_mfa
        self.verify_password = verify_password or _default_password_verifier
        self.has_password = has_password or (
            lambda user: user.hashed_password is not None
        )
        self.email_verified = email_verified or (lambda user: user.email_verified)

    @property
    def verify_url(self) -> str | None:
        return self.config.get("verify_url")

    @property
    def challenge_cookie(self) -> str:
        return self.config["challenge_cookie"]

    @property
    def challenge_ttl(self) -> int:
        return self.config["challenge_ttl"]

    # Status ---------------------------------------------------------------

    def status(self, user_id: Any) -> MFAStatus:
        factors = self.storage.list_factors(user_id)
        return MFAStatus(
            enabled=bool(factors),
            factors=[MFAFactorInfo.of(factor) for factor in factors],
            recovery_codes_remaining=self.storage.count_recovery_codes(user_id),
        )

    def _methods(self, user_id: Any, factors: Sequence[MFAFactor]) -> list[str]:
        methods = sorted({factor.type for factor in factors})
        if self.storage.count_recovery_codes(user_id):
            methods.append("recovery_code")
        return methods

    # Sign-in --------------------------------------------------------------

    def check_sign_in(self, user_id: str, login_method: str | None) -> None:
        """Raise ``MFARequired`` (without a challenge) if this sign-in needs 2FA.

        A user the accounts storage does not return is left to the caller's
        ``user_can_authenticate`` check.
        """
        user = self.accounts_storage.find_user_by_id(user_id)
        if user is None:
            return
        factors = self.storage.list_factors(user.id)
        if self.requires_mfa is not None:
            required = self.requires_mfa(user, login_method)
        else:
            required = bool(factors) and (
                self.config["require_for_providers"]
                or login_method not in self.provider_ids
            )
        if not required:
            return
        if not factors:
            raise CrossAuthException(
                "mfa_enrollment_required",
                "Two-factor authentication is required for this account; "
                "set it up before signing in",
                status_code=403,
            )
        raise MFARequired(
            user_id=str(user_id),
            login_method=login_method,
            methods=self._methods(user.id, factors),
        )

    def start_challenge(
        self, required: MFARequired, *, kind: ChallengeKind, data: dict[str, Any]
    ) -> MFARequired:
        """Store a challenge for ``required`` and return it with its token."""
        token = secrets.token_urlsafe(32)
        ttl = self.challenge_ttl
        challenge = Challenge(
            user_id=required.user_id,
            login_method=required.login_method,
            kind=kind,
            data=data,
            attempts_left=self.config["max_attempts"],
            expires_at=_now() + timedelta(seconds=ttl),
        )
        self.secondary_storage.set(
            _CHALLENGE_KEY.format(digest=_digest(token)),
            challenge.model_dump_json(),
            ttl=ttl,
        )
        self.hooks.run_after(
            "mfa.challenge",
            AfterMFAChallengeEvent(
                user_id=required.user_id,
                login_method=required.login_method,
                methods=required.methods,
            ),
        )
        return MFARequired(
            user_id=required.user_id,
            login_method=required.login_method,
            methods=required.methods,
            challenge=token,
        )

    def load_challenge(self, token: str) -> Challenge | None:
        raw = self.secondary_storage.get(_CHALLENGE_KEY.format(digest=_digest(token)))
        if raw is None:
            return None
        try:
            challenge = Challenge.model_validate_json(raw)
        except ValidationError:
            return None
        return None if challenge.expires_at < _now() else challenge

    def verify_challenge(
        self,
        token: str,
        *,
        code: str | None = None,
        recovery_code: str | None = None,
    ) -> tuple[Challenge, str]:
        """Check the sign-in's code and consume the challenge.

        Returns the challenge and the method that passed. A wrong code costs
        one of the challenge's attempts; the last one ends the challenge.
        """
        _require_one_code(code, recovery_code)
        key = _CHALLENGE_KEY.format(digest=_digest(token))
        challenge = self.load_challenge(token)
        if challenge is None:
            raise _invalid_challenge()
        try:
            method = self.check_code(
                challenge.user_id,
                code=code,
                recovery_code=recovery_code,
                purpose="sign_in",
            )
        except CrossAuthException as error:
            if error.error == "invalid_code":
                left = challenge.attempts_left - 1
                if left <= 0:
                    self.secondary_storage.delete(key)
                else:
                    remaining = int((challenge.expires_at - _now()).total_seconds())
                    self.secondary_storage.set(
                        key,
                        challenge.model_copy(
                            update={"attempts_left": left}
                        ).model_dump_json(),
                        ttl=max(remaining, 1),
                    )
            raise
        # Only the first of two concurrent verifications gets the challenge.
        if self.secondary_storage.pop(key) is None:
            raise _invalid_challenge()
        return challenge, method

    def check_code(
        self,
        user_id: Any,
        *,
        code: str | None,
        recovery_code: str | None,
        purpose: MFAVerifyPurpose,
    ) -> str:
        """Check a TOTP code or a recovery code; return ``"totp"`` or
        ``"recovery_code"``. Wrong codes count toward the account's lockout."""
        _require_one_code(code, recovery_code)
        user_key = str(user_id)
        now = _now()
        factors = self.storage.list_factors(user_id)
        locked_until = max(
            (_aware(f.locked_until) for f in factors if f.locked_until is not None),
            default=None,
        )
        if locked_until is not None and locked_until > now:
            self._verified(
                user_key, purpose, "totp" if code else "recovery_code", False, "locked"
            )
            raise CrossAuthException(
                "mfa_locked",
                "Too many wrong codes; try again later",
                status_code=429,
            )

        method = "totp" if code is not None else "recovery_code"
        passed = False
        remaining = None
        if code is not None:
            tolerance = self.config["totp_tolerance"]
            for factor in factors:
                if factor.type != "totp":
                    continue
                secret = self.cipher.decrypt(str(factor.data.get("secret", "")))
                if secret is None:
                    continue
                step = _totp.matching_step(secret, code, now=now, tolerance=tolerance)
                if step is not None and self.storage.claim_totp_step(
                    factor.id, step=step, used_at=now
                ):
                    passed = True
                    break
        else:
            assert recovery_code is not None
            passed = self.storage.use_recovery_code(
                user_id, hash_recovery_code(recovery_code), used_at=now
            )
            if passed:
                remaining = self.storage.count_recovery_codes(user_id)

        if not passed:
            if factors:
                failures = self.storage.record_failure(user_id)
                if failures >= self.config["lockout_failures"]:
                    self.storage.lock(
                        user_id,
                        until=now + timedelta(seconds=self.config["lockout_seconds"]),
                    )
            self._verified(user_key, purpose, method, False, "invalid_code")
            raise _invalid_code()

        if any(f.failed_attempts or f.locked_until is not None for f in factors):
            self.storage.reset_failures(user_id)
        self._verified(user_key, purpose, method, True, None, remaining)
        return method

    def _verified(
        self,
        user_id: str,
        purpose: MFAVerifyPurpose,
        method: str,
        success: bool,
        reason: str | None,
        recovery_codes_remaining: int | None = None,
    ) -> None:
        self.hooks.run_after(
            "mfa.verify",
            AfterMFAVerifyEvent(
                user_id=user_id,
                purpose=purpose,
                method=method,
                success=success,
                reason=reason,
                recovery_codes_remaining=recovery_codes_remaining,
            ),
        )

    # Recent authentication ------------------------------------------------

    def reauthentication_methods(self, user: User) -> list[str]:
        methods = []
        if self.has_password(user):
            methods.append("password")
        factors = self.storage.list_factors(user.id)
        if factors:
            methods.extend(self._methods(user.id, factors))
        methods.append("sign_in_again")
        return methods

    def require_recent_authentication(
        self, user: User, authenticated_at: datetime | None
    ) -> None:
        max_age = timedelta(seconds=self.config["reauthentication_max_age"])
        if (
            authenticated_at is not None
            and _now() - _aware(authenticated_at) <= max_age
        ):
            return
        raise ReauthenticationRequired(self.reauthentication_methods(user))

    def reauthenticate(
        self,
        user: User,
        *,
        password: str | None = None,
        code: str | None = None,
        recovery_code: str | None = None,
    ) -> datetime:
        """Check one proof of identity; return until when 2FA changes are allowed.

        The caller records the time on the session.
        """
        given = [
            value for value in (password, code, recovery_code) if value is not None
        ]
        if len(given) != 1:
            raise CrossAuthException(
                "invalid_request",
                "Give exactly one of password, code and recovery_code",
            )
        if password is not None:
            correct = self.has_password(user) and self.verify_password(user, password)
            self._verified(
                str(user.id),
                "reauthenticate",
                "password",
                correct,
                None if correct else "invalid_password",
            )
            if not correct:
                raise CrossAuthException(
                    "invalid_password", "The password is not correct"
                )
        else:
            self.check_code(
                user.id,
                code=code,
                recovery_code=recovery_code,
                purpose="reauthenticate",
            )
        return _now() + timedelta(seconds=self.config["reauthentication_max_age"])

    # Turning 2FA on and off -----------------------------------------------

    def start_totp_enrollment(
        self,
        user: User,
        *,
        session_id: str,
        authenticated_at: datetime | None,
        name: str | None = None,
    ) -> TotpEnrollment:
        self.require_recent_authentication(user, authenticated_at)
        if not self.config["allow_unverified_email"] and not self.email_verified(user):
            raise CrossAuthException(
                "email_not_verified",
                "Verify your email address before turning on two-factor "
                "authentication",
            )
        secret = _totp.generate_secret()
        enrollment_id = secrets.token_urlsafe(24)
        self.secondary_storage.set(
            _ENROLLMENT_KEY.format(digest=_digest(enrollment_id)),
            _Enrollment(
                user_id=str(user.id),
                session_id=session_id,
                secret=self.cipher.encrypt(secret),
                name=name,
            ).model_dump_json(),
            ttl=ENROLLMENT_TTL,
        )
        return TotpEnrollment(
            enrollment_id=enrollment_id,
            secret=secret,
            otpauth_uri=_totp.provisioning_uri(
                secret, issuer=self.issuer, account=user.email or str(user.id)
            ),
            expires_at=_now() + timedelta(seconds=ENROLLMENT_TTL),
        )

    def confirm_totp_enrollment(
        self,
        user: User,
        *,
        session_id: str,
        enrollment_id: str,
        code: str,
    ) -> TotpConfirmation:
        key = _ENROLLMENT_KEY.format(digest=_digest(enrollment_id))
        raw = self.secondary_storage.get(key)
        enrollment = None
        if raw is not None:
            try:
                enrollment = _Enrollment.model_validate_json(raw)
            except ValidationError:
                enrollment = None
        if (
            enrollment is None
            or enrollment.user_id != str(user.id)
            or enrollment.session_id != session_id
        ):
            raise CrossAuthException(
                "enrollment_not_found", "Start setting up the authenticator again"
            )
        secret = self.cipher.decrypt(enrollment.secret)
        if secret is None:
            raise CrossAuthException(
                "enrollment_not_found", "Start setting up the authenticator again"
            )
        step = _totp.matching_step(
            secret, code, now=_now(), tolerance=self.config["totp_tolerance"]
        )
        if step is None:
            self._verified(str(user.id), "enrollment", "totp", False, "invalid_code")
            raise _invalid_code()
        if self.secondary_storage.pop(key) is None:
            raise CrossAuthException(
                "enrollment_not_found", "Start setting up the authenticator again"
            )
        self._verified(str(user.id), "enrollment", "totp", True, None)

        self.hooks.run_before(
            "mfa.factor.create",
            BeforeMFAFactorCreateEvent(
                user=UserSnapshot.of(user), type="totp", name=enrollment.name
            ),
        )
        now = _now()
        factor = self.storage.create_factor(
            user_id=user.id,
            type="totp",
            name=enrollment.name,
            data={"secret": enrollment.secret},
            created_at=now,
            last_used_step=step,
        )
        codes = None
        if self.storage.count_recovery_codes(user.id) == 0:
            codes = generate_recovery_codes()
            self.storage.replace_recovery_codes(
                user.id, [hash_recovery_code(c) for c in codes], created_at=now
            )
        enabled_mfa = len(self.storage.list_factors(user.id)) == 1
        self.hooks.run_after(
            "mfa.factor.create",
            AfterMFAFactorCreateEvent(
                user_id=str(user.id), factor=factor, enabled_mfa=enabled_mfa
            ),
        )
        return TotpConfirmation(factor=MFAFactorInfo.of(factor), recovery_codes=codes)

    def regenerate_recovery_codes(
        self, user: User, *, authenticated_at: datetime | None
    ) -> list[str]:
        self.require_recent_authentication(user, authenticated_at)
        if not self.storage.list_factors(user.id):
            raise CrossAuthException(
                "mfa_not_enabled", "Two-factor authentication is not turned on"
            )
        codes = generate_recovery_codes()
        self.storage.replace_recovery_codes(
            user.id, [hash_recovery_code(c) for c in codes], created_at=_now()
        )
        self.hooks.run_after(
            "mfa.recovery_codes.regenerate",
            AfterMFARecoveryCodesRegenerateEvent(
                user_id=str(user.id), count=len(codes)
            ),
        )
        return codes

    def remove_factor(
        self, user: User, factor_id: str, *, authenticated_at: datetime | None
    ) -> MFAStatus:
        self.require_recent_authentication(user, authenticated_at)
        factor = next(
            (
                f
                for f in self.storage.list_factors(user.id)
                if str(f.id) == str(factor_id)
            ),
            None,
        )
        if factor is None:
            raise CrossAuthException(
                "factor_not_found", "No such factor", status_code=404
            )
        self.hooks.run_before(
            "mfa.factor.delete",
            BeforeMFAFactorDeleteEvent(
                user=UserSnapshot.of(user), factor_id=factor.id, type=factor.type
            ),
        )
        if not self.storage.delete_factor(user_id=user.id, factor_id=factor.id):
            raise CrossAuthException(
                "factor_not_found", "No such factor", status_code=404
            )
        enabled = bool(self.storage.list_factors(user.id))
        if not enabled:
            self.storage.replace_recovery_codes(user.id, [], created_at=_now())
        self.hooks.run_after(
            "mfa.factor.delete",
            AfterMFAFactorDeleteEvent(
                user_id=str(user.id),
                factor_id=factor.id,
                type=factor.type,
                mfa_enabled=enabled,
            ),
        )
        return self.status(user.id)


def _require_one_code(code: str | None, recovery_code: str | None) -> None:
    if (code is None) == (recovery_code is None):
        raise CrossAuthException(
            "invalid_request", "Give exactly one of code and recovery_code"
        )


def _invalid_challenge() -> CrossAuthException:
    return CrossAuthException(
        "invalid_challenge",
        "This sign-in has expired; sign in again",
    )


def challenge_json(required: MFARequired, verify_url: str | None) -> str:
    return json.dumps(
        {
            "error": required.error,
            "error_description": required.error_description,
            "methods": required.methods,
            "verify_url": verify_url,
        }
    )
