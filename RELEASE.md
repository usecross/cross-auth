---
release type: minor
---

Disconnecting a provider account now checks the current login methods and
deletes in one storage transaction. Concurrent disconnect requests cannot remove
both of a user's last two login identities. Integration-only connections do not
count as login alternatives; usable passwords do.

Custom account storage adapters must implement `disconnect_social_account` with
same-user serialization and atomic validation/deletion. SQLModel implements it
for PostgreSQL and SQLite. After-disconnect hooks run only after deletion
commits. The low-level `delete_social_account` method remains unchecked for
app-owned cleanup; HTTP disconnect routes always use the protected operation.
