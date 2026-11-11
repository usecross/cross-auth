---
release type: minor
---

Session metadata is now cleaned before it is stored. Clients choose most of it,
and the session list shows it back to users. This applies to every new session,
from any login path, and to values a `login` hook sets:

- In `client_id`, `client_name` and `user_agent`, control and other unprintable
  characters become spaces and runs of whitespace become one space. `user_agent`
  is cut to 512 characters, the other two to 255.
- `ip` must be a single IP address. IPv6 zone IDs are dropped and IPv4-mapped
  IPv6 addresses become IPv4. Anything else is stored as `None`, so pass one
  address, not a whole `X-Forwarded-For` list.
- Values left empty are stored as `None`.

Django sessions use the same cleaners. Malformed IP suffixes are now rejected
instead of silently discarded, and text cleaning uses bounded memory. Sessions
created before this release keep their stored values.
