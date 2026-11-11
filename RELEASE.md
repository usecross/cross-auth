---
release type: minor
---

Sessions now store the client's IP address. Cross-Auth's own logins, such as
`/token` and browser logins, read it from the request's client address as the
framework reports it (`request.client.host` in FastAPI), so behind a proxy run
your server so it trusts your proxies' forwarded headers, such as
`uvicorn --proxy-headers --forwarded-allow-ips=<your proxies>`. `login` hooks
see it in `event.metadata["ip"]`.

To store no IP, set `store_ip` to `False`. New sessions then store no IP, even
one passed in `metadata` or set by a `login` hook:

```python
CrossAuth(..., config={"session": {"store_ip": False}})
```

Django sessions, which already store `REMOTE_ADDR`, get the same switch:
`CROSS_AUTH["SESSION_STORE_IP"] = False`. With it off, a session clears the IP
it has the next time it is saved or used.

Cross-Auth now needs `cross-web>=0.9.0`.
