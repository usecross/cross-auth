---
release type: minor
---

Improve GitHub OAuth email selection.

- **Email selection by flow**: login prefers the stored email (falls back to
  primary, then any verified); signup prefers the verified primary email (falls
  back to any verified).
- **Noreply filtering**: GitHub noreply emails
  (`123+user@users.noreply.github.com`) are now rejected by default. Pass
  `allow_noreply_emails=True` to `GitHubProvider` to allow them.
- **Breaking**: failures to fetch `/user/emails` from GitHub now raise
  `OAuth2Exception` instead of silently setting email to `None`.
