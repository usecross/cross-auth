"""The OAuth clients of the OAuth server's tests.

``CROSS_AUTH["OAUTH_SERVER"]["get_client"]`` names ``get_client``. Tests
change ``clients`` to register or remove one.
"""

from cross_auth import OAuthClient

SPA_REDIRECT = "https://app.example.com/callback"
NATIVE_REDIRECT = "com.example.app:/callback"

clients: dict[str, OAuthClient] = {}


def reset() -> None:
    clients.clear()
    clients["spa"] = OAuthClient(client_id="spa", redirect_uris=(SPA_REDIRECT,))
    clients["native"] = OAuthClient(
        client_id="native",
        redirect_uris=(NATIVE_REDIRECT,),
        application_type="native",
    )


def get_client(client_id: str) -> OAuthClient | None:
    return clients.get(client_id)


reset()
