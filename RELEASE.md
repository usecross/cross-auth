---
release type: minor
---

Add shared SQLModel bases for typed model access and explicit session sorting.
The storage adapters now require table models to inherit the corresponding base
from `cross_auth.storage.sqlmodel`:

- User models: `SQLModelUser`.
- Social account models: `SQLModelSocialAccount`.
- Session models: `SQLModelSession`.

**Breaking change:** models that only inherit `SQLModel` are no longer accepted
by these adapters. Update their base classes when upgrading; otherwise storage
initialization raises `TypeError`. Apply this change to database models, not
shared API request or response schemas.

Existing field declarations can remain as overrides. Applications still define
IDs, relationships, verification, provider credential fields, and identity
constraints. Property-backed verification and credentials remain supported.
Session models inherit timestamps, client metadata, and the computed `status`
property. Review the resulting columns and indexes before generating migrations;
no database migration is needed if the schema is unchanged.
