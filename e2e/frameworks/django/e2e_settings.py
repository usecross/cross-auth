"""The Django example's settings, pointed at the Google emulator.

The shared browser suite starts ``examples/django`` with these settings: its
own SQLite file per worker, and Google served by the local emulator. The
example's views, templates, signals and middleware stay as they are.
"""

import os

from config.settings import *  # noqa: F403
from config.settings import DATABASES

from cross_auth.social_providers.google import GoogleProvider

EMULATOR_URL = os.environ["GOOGLE_EMULATOR_URL"]


class EmulatedGoogleProvider(GoogleProvider):
    # The emulator signs ID tokens with its own URL as issuer. Signature,
    # audience, nonce and PKCE checks are unchanged.
    issuer = EMULATOR_URL
    jwks_cache_key = "google-emulator:jwks"


DATABASES["default"]["NAME"] = os.environ["E2E_DATABASE"]

CROSS_AUTH = {
    "PROVIDERS": [
        EmulatedGoogleProvider(
            client_id=os.environ["GOOGLE_CLIENT_ID"],
            client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
            authorization_endpoint=f"{EMULATOR_URL}/o/oauth2/v2/auth",
            token_endpoint=f"{EMULATOR_URL}/oauth2/token",
            jwks_uri=f"{EMULATOR_URL}/oauth2/v3/certs",
        ),
    ],
}
