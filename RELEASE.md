---
release type: minor
---

New-user signup now commits the user, provider identity, and required
application rows together. A failed identity write or before-create hook rolls
back the whole signup. After-create hooks run only after that transaction
commits.

Custom account storage adapters must implement `create_user_with_identity` with
one transaction. SQLModel provides this operation and a public `build_user`
extension for related application records. Move external side effects to after
hooks; failures there cannot undo committed signup. Concurrent signup conflicts
retain the backend integrity error and roll back the losing request's records.
