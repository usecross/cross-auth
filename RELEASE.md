---
release type: patch
---

CrossAuth now calls `AccountsStorage.find_user_by_email` once when an OAuth
identity has no linked social account. This removes redundant storage work for
new sign-ins while preserving normalized-email, automatic-linking,
account-conflict, and verified-email behavior.
