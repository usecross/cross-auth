"""What a session's stored user agent says about the device behind it."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Annotated

from pydantic import Field
from ua_parser import parse

# uap-core names the mobile builds of desktop browsers apart; `mobile` already
# says the session is on a phone or tablet.
_BROWSER_NAMES = {
    "Chrome Mobile": "Chrome",
    "Chrome Mobile iOS": "Chrome",
    "Edge Mobile": "Edge",
    "Firefox iOS": "Firefox",
    "Firefox Mobile": "Firefox",
    "Mobile Safari": "Safari",
}
_OS_NAMES = {"Mac OS X": "macOS"}
# User agents name the operating system, not the kind of device: an Android TV
# counts as mobile, and an iPad that asks for desktop sites sends a Mac's user
# agent.
_MOBILE_OSES = frozenset({"Android", "BlackBerry OS", "KaiOS", "Windows Phone", "iOS"})

# RFC 9110 §10.1.5: User-Agent = product *( RWS ( product / comment ) ), where
# product = token [ "/" product-version ] and comments are parenthesized and
# can nest.
_TOKEN = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
_PRODUCT = re.compile(rf"({_TOKEN})(?:/({_TOKEN}))?")


# Dataclasses, not pydantic models, so that Django's SessionInfo, a dataclass
# too, still works with dataclasses.asdict().
@dataclass(frozen=True)
class SessionProduct:
    """One of the products a user agent lists, such as "my-cli/1.2.0"."""

    name: str
    version: str | None


@dataclass(frozen=True)
class SessionDevice:
    """What a session's user agent says about the device behind it."""

    browser: Annotated[
        str | None,
        Field(description='The browser or other client, such as "Chrome" or "curl"'),
    ]
    os: Annotated[
        str | None,
        Field(description='The operating system, such as "macOS", "Windows" or "iOS"'),
    ]
    mobile: Annotated[
        bool,
        Field(
            description="Whether the operating system is a phone or tablet one, "
            "such as iOS or Android"
        ),
    ]
    products: Annotated[
        tuple[SessionProduct, ...],
        Field(
            description="The products the user agent lists, most significant "
            "first, as RFC 9110 defines them; empty when it does not follow "
            "that grammar"
        ),
    ]


def _products(user_agent: str) -> tuple[SessionProduct, ...]:
    """The products ``user_agent`` lists, in order, without its comments.

    Empty when the user agent does not follow RFC 9110's grammar.
    """
    products: list[SessionProduct] = []
    position, depth = 0, 0
    while position < len(user_agent):
        char = user_agent[position]
        if depth:
            if char == "\\":
                position += 1
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            position += 1
        elif char == "(":
            depth = 1
            position += 1
        elif char.isspace():
            position += 1
        elif match := _PRODUCT.match(user_agent, position):
            products.append(SessionProduct(name=match[1], version=match[2]))
            position = match.end()
        else:
            return ()

    return () if depth else tuple(products)


def describe_user_agent(user_agent: str | None) -> SessionDevice | None:
    """Return what a user agent says about the device, or ``None`` if it says
    nothing: it names no browser or operating system and lists no products.

    Browsers and operating systems are parsed with ``ua-parser``, which caches
    the user agents it has seen.
    """
    if not user_agent:
        return None

    result = parse(user_agent)
    browser = result.user_agent.family if result.user_agent else None
    os = result.os.family if result.os else None
    products = _products(user_agent)
    if browser is None and os is None and not products:
        return None

    return SessionDevice(
        browser=_BROWSER_NAMES.get(browser, browser) if browser else None,
        os=_OS_NAMES.get(os, os) if os else None,
        mobile=os in _MOBILE_OSES,
        products=products,
    )
