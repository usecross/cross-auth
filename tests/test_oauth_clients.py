import pytest
from pydantic import ValidationError

from cross_auth._clients import OAuthClient


def client(uri, application_type="web"):
    return OAuthClient.model_validate(
        {
            "client_id": "app",
            "redirect_uris": [uri],
            "application_type": application_type,
        }
    )


def test_registration_is_immutable_and_keeps_original_strings():
    original = "https://APP.example/callback?x=%2f"
    registered = client(original)

    assert registered.redirect_uris == (original,)
    assert registered.check_redirect_uri(original)
    with pytest.raises(ValidationError, match="frozen"):
        registered.client_id = "changed"


@pytest.mark.parametrize(
    "uri",
    [
        "https://app.example/callback/",
        "https://app.example/other",
        "https://app.example/callback?x=1",
        "https://app.example/callback?",
        "https://app.example:443/callback",
        "https://APP.example/callback",
        "https://app.example/call%62ack",
        "https://app.example.evil/callback",
    ],
)
def test_web_redirects_require_exact_strings(uri):
    assert not client("https://app.example/callback").check_redirect_uri(uri)


@pytest.mark.parametrize(
    "uri",
    [
        "https://app.example/callback",
        "http://localhost:5173/callback",
        "http://127.0.0.1:8000/callback",
    ],
)
def test_web_http_and_https_registrations(uri):
    assert client(uri).check_redirect_uri(uri)


@pytest.mark.parametrize(
    "uri",
    [
        "",
        "/relative",
        "//app.example/callback",
        "https:///callback",
        "https://user@app.example/callback",
        "https://user:pass@app.example/callback",
        "https://*.example/callback",
        "https://app.example/callback#",
        "https://app.example/callback#fragment",
        "https://app.example/\\evil",
        " https://app.example/callback",
        "https://app.example/call\nback",
        "https://app.example/callback\x00",
        "https://app.example/callback\x7f",
        "https://app.example/callback\x80",
        "https://[::1]evil/callback",
        "https://app.example/\ud800",
        "https://app.example/café",
        "https://app^example/callback",
        "https://app.example:bad/callback",
        "https://app.example:65536/callback",
        "https://app.example:/callback",
        "https://%61pp.example/callback",
        "https://[not-ip]/callback",
        "javascript:alert(1)",
    ],
)
def test_invalid_registrations_and_requests(uri):
    with pytest.raises(
        ValidationError, match="Value error|valid URL|strict URL syntax"
    ):
        client(uri)

    assert not client("https://app.example/callback").check_redirect_uri(uri)


@pytest.mark.parametrize(
    "suffix", ["with space", "with\nnewline", "\\evil", "\x00", "\x7f"]
)
def test_native_private_scheme_rejects_invalid_url_syntax(suffix):
    uri = f"com.example.app:/callback/{suffix}"

    with pytest.raises(ValidationError, match="strict URL syntax"):
        client(uri, "native")

    assert not client("com.example.app:/callback", "native").check_redirect_uri(uri)


@pytest.mark.parametrize(
    "uri",
    [
        "com.example.app:/callback",
        "https://app.example/callback",
        "http://127.0.0.1:1234/callback",
        "http://[::1]:1234/callback",
    ],
)
def test_native_supported_redirect_types(uri):
    assert client(uri, "native").check_redirect_uri(uri)


@pytest.mark.parametrize(
    "uri",
    [
        "http://app.example/callback",
        "http://localhost:1234/callback",
        "http://127.1:1234/callback",
        "http://2130706433:1234/callback",
        "http://127.0.0.2:1234/callback",
        "http://[0:0:0:0:0:0:0:1]:1234/callback",
        "app:/callback",
        "com.example.app:callback",
        "com.example.app://callback",
        "com.example.app:///callback",
        "com..app:/callback",
        "com.example-.app:/callback",
        "file:/callback",
        "data:/callback",
        "javascript:/callback",
    ],
)
def test_native_rejects_ambiguous_or_non_native_uris(uri):
    with pytest.raises(ValidationError):
        client(uri, "native")


@pytest.mark.parametrize("host", ["127.0.0.1", "[::1]"])
def test_only_native_http_loopback_ports_may_vary(host):
    registered = client(f"http://{host}:8000/callback?x=%2f", "native")

    assert registered.check_redirect_uri(f"http://{host}:54321/callback?x=%2f")
    assert registered.check_redirect_uri(f"http://{host}/callback?x=%2f")
    assert not registered.check_redirect_uri(f"http://{host}:54321/callback?x=%2F")
    assert not registered.check_redirect_uri(f"http://{host}:54321/callback/?x=%2f")
    assert not registered.check_redirect_uri(f"HTTP://{host}:54321/callback?x=%2f")
    assert not client(f"http://{host}:8000/callback").check_redirect_uri(
        f"http://{host}:54321/callback"
    )
    assert not client(f"https://{host}:8000/callback", "native").check_redirect_uri(
        f"https://{host}:54321/callback"
    )


@pytest.mark.parametrize(
    "uri",
    [
        "http://127.0.0.1:54321/callback?",
        "http://[::1]:54321/callback",
        "http://127.0.0.1.evil:54321/callback",
        "http://127.0.0.1:54321@evil/callback",
        "http://127.0.0.1:54321/other",
        "http://127.0.0.1:54321/call%62ack",
    ],
)
def test_loopback_exception_does_not_change_other_uri_parts(uri):
    assert not client("http://127.0.0.1/callback", "native").check_redirect_uri(uri)


def test_empty_client_id_is_invalid():
    with pytest.raises(ValidationError, match="at least 1 character"):
        OAuthClient(client_id="", redirect_uris=())


def test_percent_encoded_non_ascii_redirect_is_preserved():
    uri = "https://app.example/caf%C3%A9"

    assert client(uri).check_redirect_uri(uri)
    assert not client(uri).check_redirect_uri("https://app.example/caf%c3%a9")
