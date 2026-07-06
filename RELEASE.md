Release type: patch

A token-less sign-in — `sign_in_with_id_token`, where no OAuth code exchange
happens — no longer overwrites provider credentials stored on the social account
by an earlier web flow. Previously a repeat sign-in through the native path
nulled the stored access/refresh tokens and scope, silently breaking apps that
call the provider's API later (e.g. a Google refresh token used for background
calendar sync). Identity fields (`provider_email`, `provider_email_verified`,
user info) still refresh from the new token's claims; a web code exchange, which
always carries an access token, updates credentials exactly as before.

The `SocialAccount` protocol now declares the credential fields (`access_token`,
`refresh_token`, their expiries, and `scope`) as read-only properties. Storages
were already required to accept them as
`update_social_account`/`create_social_account` keyword arguments; declaring
them readable is what lets core preserve stored values, and models built for the
documented adapters already expose them.
