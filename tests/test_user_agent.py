import pytest

from cross_auth._user_agent import SessionDevice, SessionProduct, describe_user_agent

CHROME_MAC = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
SAFARI_MAC = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/18.1 Safari/605.1.15"
)
EDGE_WINDOWS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"
)
FIREFOX_LINUX = "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0"
SAFARI_IPHONE = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1"
)
CHROME_IPAD = (
    "Mozilla/5.0 (iPad; CPU OS 18_1 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) CriOS/131.0.6778.73 Mobile/15E148 Safari/604.1"
)
CHROME_ANDROID = (
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"
)
FIREFOX_ANDROID = "Mozilla/5.0 (Android 14; Mobile; rv:132.0) Gecko/132.0 Firefox/132.0"
WINDOWS_PHONE = (
    "Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Microsoft; Lumia 950) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Mobile "
    "Safari/537.36 Edge/15.14977"
)


@pytest.mark.parametrize(
    ("user_agent", "browser", "os", "mobile"),
    [
        (CHROME_MAC, "Chrome", "macOS", False),
        (SAFARI_MAC, "Safari", "macOS", False),
        (EDGE_WINDOWS, "Edge", "Windows", False),
        (FIREFOX_LINUX, "Firefox", "Linux", False),
        (SAFARI_IPHONE, "Safari", "iOS", True),
        (CHROME_IPAD, "Chrome", "iOS", True),
        (CHROME_ANDROID, "Chrome", "Android", True),
        (FIREFOX_ANDROID, "Firefox", "Android", True),
        (WINDOWS_PHONE, "Edge", "Windows Phone", True),
        ("curl/8.7.1", "curl", None, False),
        ("my-cli/1.2.0", None, None, False),
    ],
)
def test_names_the_browser_and_os(
    user_agent: str, browser: str | None, os: str | None, mobile: bool
):
    device = describe_user_agent(user_agent)

    assert device is not None
    assert (device.browser, device.os, device.mobile) == (browser, os, mobile)


@pytest.mark.parametrize(
    ("user_agent", "products"),
    [
        (
            CHROME_MAC,
            [
                ("Mozilla", "5.0"),
                ("AppleWebKit", "537.36"),
                ("Chrome", "131.0.0.0"),
                ("Safari", "537.36"),
            ],
        ),
        ("my-cli/1.2.0 extension/3", [("my-cli", "1.2.0"), ("extension", "3")]),
        ("Laptop", [("Laptop", None)]),
        ("a/1 (nested (comment) and \\) an escaped one) b/2", [("a", "1"), ("b", "2")]),
    ],
)
def test_lists_the_products_without_comments(
    user_agent: str, products: list[tuple[str, str | None]]
):
    device = describe_user_agent(user_agent)

    assert device is not None
    assert device.products == tuple(
        SessionProduct(name=name, version=version) for name, version in products
    )


@pytest.mark.parametrize(
    "user_agent", ["a/1 b@2", "a/", "a/1 (no closing parenthesis", "a/1 )"]
)
def test_lists_no_products_outside_the_grammar(user_agent: str):
    assert describe_user_agent(user_agent) is None


def test_a_browser_outside_the_grammar_is_still_named():
    in_app = SAFARI_IPHONE + " [FBAN/FBIOS;FBAV/490.0]"

    assert describe_user_agent(in_app) == SessionDevice(
        browser="Facebook", os="iOS", mobile=True, products=()
    )


@pytest.mark.parametrize("user_agent", [None, ""])
def test_returns_none_without_a_user_agent(user_agent: str | None):
    assert describe_user_agent(user_agent) is None
