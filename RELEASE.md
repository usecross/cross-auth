---
release type: patch
---

Hook dispatch now consistently rejects unsupported event names with a clear
`ValueError`, whether the event is being registered or run.
