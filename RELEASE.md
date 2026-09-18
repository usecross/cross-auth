---
release type: minor
---

User models may omit a `social_accounts` relationship or property; use the
storage adapter's `list_social_accounts` operation for account access.

**Breaking change:** the SQLModel adapter no longer automatically loads
`social_accounts`. Applications that access this relationship after the storage
session closes must configure loading on their model:

```python
social_accounts: list[SocialAccount] = Relationship(
    back_populates="user",
    sa_relationship_kwargs={"lazy": "selectin"},
)
```

Preserve any other relationship options already configured by your application.
This changes ORM loading behavior only; foreign keys and database schemas are
unchanged, and no database migration is needed.
