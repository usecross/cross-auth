---
release type: minor
---

**Breaking:** `SQLModelSession` now declares `token_hash` with a unique index,
`Field(unique=True, index=True)`, instead of a plain one. Every authenticated
request looks its session up by this hash, so the database now makes sure each
hash belongs to exactly one session. Session models no longer need to redeclare
`token_hash` to get that: they only declare their `id` and `user_id`.

Tables created by earlier versions keep their non-unique index until you migrate
them, and Alembic's autogenerate (and `alembic check`) now reports a dropped and
re-added `ix_<table>_token_hash`. Cross-Auth's session tokens are random 256-bit
values, so no two sessions should share a hash, but check before migrating:

```sql
SELECT token_hash, COUNT(*) FROM usersession GROUP BY token_hash HAVING COUNT(*) > 1;
```

If it finds any, delete those rows first; the devices using them have to sign in
again. Then recreate the index as unique:

```python
op.drop_index("ix_usersession_token_hash", table_name="usersession")
op.create_index("ix_usersession_token_hash", "usersession", ["token_hash"], unique=True)
```

If your session model already redeclared
`token_hash: str = Field(unique=True, index=True)`, your table already has this
index: drop the override, and there is nothing to migrate.

Django's `cross_auth.django.models.Session` is unchanged: it is keyed by its
`session_key` primary key, so there is no new Django migration.
