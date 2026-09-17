import pytest
from cross_web import HTTPRequest, TestingHTTPRequestAdapter

from cross_auth import get_bearer_token


@pytest.mark.parametrize("header", ["Authorization", "authorization", "AUTHORIZATION"])
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("Bearer token", "token"),
        ("bearer token", "token"),
        ("BEARER token", "token"),
        ("Bearer   token  ", "token"),
        ("", None),
        ("Bearer", None),
        ("Bearer   ", None),
        ("Basic token", None),
    ],
)
def test_get_bearer_token(header: str, value: str, expected: str | None):
    request = HTTPRequest(TestingHTTPRequestAdapter(headers={header: value}))

    assert get_bearer_token(request) == expected


def test_missing_authorization_header():
    request = HTTPRequest(TestingHTTPRequestAdapter())

    assert get_bearer_token(request) is None
