---
release type: minor
---

This release makes auth routes and hooks synchronous, allowing applications that
use synchronous dependencies such as database clients to run auth logic without
blocking the event loop.

It also updates Cross Auth to use `cross-web`'s synchronous `HTTPRequest`
wrapper.
