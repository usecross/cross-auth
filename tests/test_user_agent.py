import pytest

from cross_auth._user_agent import SessionDevice, describe_user_agent

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


@pytest.mark.parametrize(
    ("user_agent", "device"),
    [
        (CHROME_MAC, SessionDevice(browser="Chrome", os="macOS", mobile=False)),
        (SAFARI_MAC, SessionDevice(browser="Safari", os="macOS", mobile=False)),
        (EDGE_WINDOWS, SessionDevice(browser="Edge", os="Windows", mobile=False)),
        (FIREFOX_LINUX, SessionDevice(browser="Firefox", os="Linux", mobile=False)),
        (SAFARI_IPHONE, SessionDevice(browser="Safari", os="iOS", mobile=True)),
        (CHROME_IPAD, SessionDevice(browser="Chrome", os="iOS", mobile=True)),
        (CHROME_ANDROID, SessionDevice(browser="Chrome", os="Android", mobile=True)),
        (FIREFOX_ANDROID, SessionDevice(browser="Firefox", os="Android", mobile=True)),
        ("curl/8.7.1", SessionDevice(browser="curl", os=None, mobile=False)),
    ],
)
def test_describes_browsers_and_clients(user_agent: str, device: SessionDevice):
    assert describe_user_agent(user_agent) == device


@pytest.mark.parametrize("user_agent", [None, "", "my-cli/1.0", "Laptop"])
def test_returns_none_when_it_names_no_browser_or_os(user_agent: str | None):
    assert describe_user_agent(user_agent) is None
