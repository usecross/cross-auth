---
release type: patch
---

Extract framework-independent authentication setup so the FastAPI facade and
router share one context, provider registry, and token issuer. Preserve public
constructor signatures and existing routes. Facade operations now read the
shared context directly, so later context-attribute reassignment also affects
those operations instead of leaving construction-time copies behind.
