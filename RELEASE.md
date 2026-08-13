---
release type: patch
---

OAuth callback routes now use distinct OpenAPI operation IDs for GET and POST
requests. This removes FastAPI's duplicate operation ID warning and allows
OpenAPI client generators to produce unambiguous callback methods while
preserving the existing operation ID for standard GET callbacks.
