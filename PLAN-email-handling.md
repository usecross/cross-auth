# Plan: Email Handling for Social Providers

## Problem Statement

Currently, cross-auth **fails hard** if a provider doesn't return a verified email:
- `GitHubProvider.fetch_user_info()` raises `ValueError("No verified email found")`
- `OAuth2Provider.validate_user_info()` raises `OAuth2Exception` if no email

This is too rigid. We need to:
1. Handle missing/unverified emails gracefully
2. Store email verification status
3. Support account linking by email

---

## Design Decisions

1. **Email is required on User** - `User.email: str` (not optional)
2. **No per-provider EmailConfig** - keep it simple
3. **Global AccountLinkingConfig only** - trusted_providers, link_by_email, etc.
4. **Providers handle their own quirks internally** - e.g., GitHub filters noreply emails as an implementation detail

---

## Changes Required

### 1. Storage Protocol Changes (`_storage.py`)

```python
class User(Protocol):
    id: Any
    email: str                    # Required
    email_verified: bool          # NEW
    hashed_password: str | None

    @property
    def social_accounts(self) -> Iterable[SocialAccount]: ...


class SocialAccount(Protocol):
    id: Any
    user_id: Any
    provider_user_id: str
    provider: str
    provider_email: str | None           # NEW: Email from this provider
    provider_email_verified: bool | None # NEW: Provider's verification status
    is_login_method: bool                # NEW: For login method constraint
```

**AccountsStorage changes:**
```python
def create_user(
    self,
    *,
    user_info: dict[str, Any],
    email: str,              # NEW: explicit
    email_verified: bool,    # NEW: explicit
) -> User: ...

def create_social_account(
    self,
    *,
    # ... existing params ...
    provider_email: str | None,          # NEW
    provider_email_verified: bool | None, # NEW
    is_login_method: bool = True,         # NEW
) -> SocialAccount: ...
```

### 2. Account Linking Config (`_config.py` - NEW FILE)

```python
from dataclasses import dataclass


@dataclass
class AccountLinkingConfig:
    """Global account linking configuration."""

    # Automatically link accounts by verified email?
    link_by_email: bool = False

    # Providers to trust (bypass verification checks for linking)
    # None = trust all, [] = trust none
    trusted_providers: list[str] | None = None

    # Allow linking accounts with different emails?
    allow_different_emails: bool = False

    def is_trusted_provider(self, provider_id: str) -> bool:
        if self.trusted_providers is None:
            return True
        return provider_id in self.trusted_providers
```

### 3. Context Changes (`_context.py`)

```python
@dataclass
class Context:
    secondary_storage: SecondaryStorage
    accounts_storage: AccountsStorage
    create_token: Callable[[str], tuple[str, int]]
    trusted_origins: list[str]
    get_user_from_request: Callable[[AsyncHTTPRequest], User | None]
    base_url: str | None = None
    account_linking: AccountLinkingConfig = field(default_factory=AccountLinkingConfig)  # NEW
```

### 4. Provider Base Class Changes (`social_providers/oauth.py`)

```python
def validate_user_info(self, user_info: dict) -> tuple[str, str, bool | None]:
    """
    Returns: (email, provider_user_id, email_verified)

    Raises OAuth2Exception if email is missing.
    """
    provider_user_id = user_info.get("id")
    if not provider_user_id:
        raise OAuth2Exception(...)

    email = user_info.get("email")
    if not email:
        raise OAuth2Exception(
            error="email_required",
            error_description="Provider did not return an email address",
        )

    email_verified = user_info.get("email_verified")  # bool | None

    return email, str(provider_user_id), email_verified
```

### 5. GitHub Provider Changes (`social_providers/github.py`)

```python
class GitHubProvider(OAuth2Provider):
    id = "github"
    # ... existing class vars ...

    def fetch_user_info(self, token: str) -> dict:
        info = super().fetch_user_info(token)

        try:
            response = httpx.get(
                "https://api.github.com/user/emails",
                headers={"Authorization": f"Bearer {token}"},
            )
            response.raise_for_status()
            emails = response.json()

            # Filter out noreply emails (internal implementation detail)
            emails = [
                e for e in emails
                if not e["email"].endswith("@users.noreply.github.com")
            ]

            # Find primary verified email
            primary_verified = next(
                (e for e in emails if e["primary"] and e["verified"]),
                None,
            )

            if primary_verified:
                info["email"] = primary_verified["email"]
                info["email_verified"] = True
            else:
                # Try any verified email
                any_verified = next(
                    (e for e in emails if e["verified"]),
                    None,
                )
                if any_verified:
                    info["email"] = any_verified["email"]
                    info["email_verified"] = True
                else:
                    # Try primary unverified
                    primary = next((e for e in emails if e["primary"]), None)
                    if primary:
                        info["email"] = primary["email"]
                        info["email_verified"] = False
                    else:
                        # No usable email
                        info["email"] = None
                        info["email_verified"] = None

        except Exception as e:
            logger.error(f"Failed to fetch user emails: {e}")
            info["email"] = None
            info["email_verified"] = None

        # Ensure name fallback
        if not info.get("name"):
            info["name"] = info["login"]

        return info
```

### 6. Callback Flow Changes (`social_providers/oauth.py`)

```python
async def callback(self, request: AsyncHTTPRequest, context: Context) -> Response:
    # ... existing code until validate_user_info ...

    try:
        token_response = self.exchange_code(...)
        user_info = self.fetch_user_info(token_response.access_token)
        email, provider_user_id, email_verified = self.validate_user_info(user_info)
    except OAuth2Exception as e:
        return Response.error_redirect(...)

    social_account = context.accounts_storage.find_social_account(
        provider=self.id,
        provider_user_id=provider_user_id,
    )

    if social_account:
        # Existing social account - update and login
        context.accounts_storage.update_social_account(
            social_account.id,
            # ... existing fields ...
            provider_email=email,
            provider_email_verified=email_verified,
        )
        user = context.accounts_storage.find_user_by_id(social_account.user_id)
    else:
        # New social account
        user = None

        # Try to find user by email (if email linking enabled)
        if context.account_linking.link_by_email:
            user = context.accounts_storage.find_user_by_email(email)
            # TODO: Check linking requirements based on AccountLinkingConfig

        if not user:
            # Create new user
            user = context.accounts_storage.create_user(
                user_info=user_info,
                email=email,
                email_verified=email_verified or False,
            )

        # Create social account
        context.accounts_storage.create_social_account(
            user_id=user.id,
            provider=self.id,
            provider_user_id=provider_user_id,
            provider_email=email,
            provider_email_verified=email_verified,
            is_login_method=True,  # First connection = login method
            # ... other fields ...
        )

    # ... rest of flow ...
```

---

## Migration Path

### Breaking Changes

1. `User` protocol now has `email_verified` (required field)
2. `SocialAccount` protocol has new fields: `provider_email`, `provider_email_verified`, `is_login_method`
3. `AccountsStorage.create_user()` signature changed (new `email`, `email_verified` params)
4. `AccountsStorage.create_social_account()` signature changed (new fields)
5. `validate_user_info()` return type changed: `tuple[str, str]` → `tuple[str, str, bool | None]`

### For Existing Users

Apps implementing `AccountsStorage` will need to:
1. Add `email_verified` column to users table
2. Add `provider_email`, `provider_email_verified`, `is_login_method` to social_accounts table
3. Update storage methods to handle new fields

---

## Test Cases to Add

1. GitHub user with verified email → Success, `email_verified=True`
2. GitHub user with only noreply email → Error (filtered out, no email)
3. GitHub user with unverified email → Success, `email_verified=False`
4. Email linking: same email, provider verified, `link_by_email=True` → Link succeeds
5. Email linking: same email, `link_by_email=False` → New user created (no linking)
6. `is_login_method` constraint: same GitHub can connect to multiple users

---

## Implementation Order

1. [ ] Add `AccountLinkingConfig` dataclass
2. [ ] Update `User` protocol (add `email_verified`)
3. [ ] Update `SocialAccount` protocol (add new fields)
4. [ ] Update `AccountsStorage` protocol (new method signatures)
5. [ ] Update `OAuth2Provider.validate_user_info()` to return verification status
6. [ ] Update `GitHubProvider.fetch_user_info()` to filter noreply, return status
7. [ ] Update `OAuth2Provider.callback()` to handle new fields
8. [ ] Update `OAuth2Provider.finalize_link()` similarly
9. [ ] Update `Context` to include `AccountLinkingConfig`
10. [ ] Update tests
11. [ ] Update DiscordProvider similarly

---

## Summary

| Level | Config |
|-------|--------|
| **Global** | `AccountLinkingConfig` (trusted_providers, link_by_email, allow_different_emails) |
| **Per-provider** | None - just `client_id`, `client_secret` |
| **Internal** | Providers handle their own quirks (GitHub filters noreply) |

No `EmailConfig` class. Keep it simple.
