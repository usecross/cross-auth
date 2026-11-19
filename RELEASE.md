Release type: minor

Session lists now say which browser and operating system each session is on, so
a page can show "Chrome on macOS" instead of the raw `User-Agent` header.
`GET /sessions` gives each session a `device`, and so does the Django
integration's `list_sessions(request)`:

```json
"device": { "browser": "Chrome", "os": "macOS", "mobile": false }
```

`browser` can also be another client, such as `"curl"`, and `mobile` is true for
phones and tablets. `device` is `null` (`None` in Django) when the user agent
names neither a browser nor an operating system.

Cross-Auth parses the stored user agent with
[`ua-parser`](https://pypi.org/project/ua-parser/), a new dependency, each time
it lists sessions, so nothing new is stored and older sessions are described
too.
