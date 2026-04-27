---
release type: patch
---

This release fixes the OpenAPI schema for disconnecting a specific linked OAuth
account.

The `DELETE /{provider}/social-accounts/{social_account_id}` route now documents
its required `social_account_id` path parameter, so generated clients and API
docs correctly show the account-specific disconnect endpoint.
