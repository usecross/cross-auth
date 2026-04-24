---
release type: minor
---

This release adds provider-level hooks for advanced OAuth flows. Providers now
receive the incoming request when building authorization URLs, can intercept
callbacks before the standard OAuth handler runs, and can post-process final
redirect responses.
