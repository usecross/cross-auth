---
release type: minor
---

This release adds support for disconnecting linked OAuth provider accounts.

Applications can now expose `DELETE /{provider}/social-accounts` to disconnect
the current user's provider account when only one account for that provider is
connected, or `DELETE /{provider}/social-accounts/{social_account_id}` to
disconnect a specific linked account.

Cross Auth prevents users from removing their only login method by checking for
a usable password or another login-enabled social account. The new
`oauth.disconnect` hooks let applications block disconnects, revoke provider
tokens, clear caches, or audit successful account removals.

Storage backends can support this flow through new social-account lookup,
listing, and deletion methods on the accounts storage protocol.
