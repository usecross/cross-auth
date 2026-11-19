Release type: minor

Session lists now describe the device behind each session, so a page can show
"Chrome on macOS" instead of the raw `User-Agent` header. `GET /sessions` gives
each session a `device`, and so does the Django integration's
`list_sessions(request)`:

```json
"device": {
  "browser": "Chrome",
  "os": "macOS",
  "mobile": false,
  "products": [
    { "name": "Mozilla", "version": "5.0" },
    { "name": "AppleWebKit", "version": "537.36" },
    { "name": "Chrome", "version": "131.0.0.0" },
    { "name": "Safari", "version": "537.36" }
  ]
}
```

- `browser` can also be another client, such as `"curl"`. Many browsers, such as
  Arc, Brave and Dia, send Chrome's user agent, so they are listed as Chrome.
- `mobile` is true when the operating system is a phone or tablet one, such as
  iOS or Android. User agents name the operating system, not the kind of device,
  so an Android TV counts as mobile, and an iPad that asks for desktop sites
  sends a Mac's user agent and doesn't.
- `products` lists the user agent's `name/version` products, most significant
  first, as RFC 9110 defines them, so a client that `browser` doesn't know, such
  as `my-cli/1.2.0`, is still described.
- `device` is `null` (`None` in Django) without a user agent, or when it names
  no browser or operating system and lists no products.

`describe_user_agent(user_agent)` gives the same `device` for pages built on
`auth.list_sessions()`.

Cross-Auth parses the stored user agent each time it lists sessions, so nothing
new is stored and older sessions are described too. Browsers and operating
systems come from [`ua-parser`](https://pypi.org/project/ua-parser/), a new
dependency.
