---
release type: minor
---

The OAuth server can now sign users in on CLIs and other input-constrained
clients with the OAuth 2.0 Device Authorization Grant
([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)). The device shows a short
code, the user approves it on a page of your application, and the device polls
`/token` for its token. It is off until you pass `device` to `OAuthServer`:

```python
from cross_auth import DeviceGrant, OAuthClient, OAuthServer

clients = {
    "example-cli": OAuthClient(
        client_id="example-cli",
        client_name="Example CLI",
        redirect_uris=(),
    ),
}

oauth_server = OAuthServer(
    get_client=clients.get,
    device=DeviceGrant(verification_uri="https://example.com/device"),
)
```

- `POST /device/code` gives the device a device code and a user code such as
  `BCDF-GHJK`. `/token` accepts
  `grant_type=urn:ietf:params:oauth:grant-type:device_code` and answers
  `authorization_pending`, `slow_down`, `access_denied` or `expired_token` until
  the user decides.
- Your approval page looks the request up, then approves or denies it for the
  signed-in user: with `GET /device`, `POST /device/approve` and
  `POST /device/deny`, or with `auth.get_device_authorization()`,
  `auth.approve_device_authorization()` and `auth.deny_device_authorization()`.
- The session is created when the device polls, through the `login` hooks and
  with `login_method="device"`. `user_can_authenticate` is asked when the user
  approves and again then.
- New hooks: `device.code`, whose before hook can attach metadata the approval
  page reads back, `device.approve`, and `token.device_code`.
- `OAuthClient` gains an optional `client_name`, which the grant shows on the
  approval page and stores on its sessions. `TokenIssueRequest.grant_type` can
  be `"device_code"`.
- The state lives in `SecondaryStorage`, under hashes of the codes, so there is
  nothing to migrate.

The Django integration does not offer the grant yet.
