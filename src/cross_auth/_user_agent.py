"""What a session's stored user agent says about the device behind it."""

from __future__ import annotations

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
_MOBILE_OSES = frozenset({"Android", "iOS"})


# A dataclass, not a pydantic model, so that Django's SessionInfo, a dataclass
# too, still works with dataclasses.asdict().
@dataclass(frozen=True)
class SessionDevice:
    """The browser and operating system that a session's user agent names."""

    browser: Annotated[
        str | None,
        Field(description='The browser or other client, such as "Chrome" or "curl"'),
    ]
    os: Annotated[
        str | None,
        Field(description='The operating system, such as "macOS", "Windows" or "iOS"'),
    ]
    mobile: Annotated[
        bool, Field(description="Whether the device is a phone or a tablet")
    ]


def describe_user_agent(user_agent: str | None) -> SessionDevice | None:
    """Return the device a user agent names, or ``None`` if it names neither
    a browser nor an operating system.

    Parsed with ``ua-parser``, which caches the user agents it has seen.
    """
    if not user_agent:
        return None

    result = parse(user_agent)
    browser = result.user_agent.family if result.user_agent else None
    os = result.os.family if result.os else None
    if browser is None and os is None:
        return None

    return SessionDevice(
        browser=_BROWSER_NAMES.get(browser, browser) if browser else None,
        os=_OS_NAMES.get(os, os) if os else None,
        mobile=os in _MOBILE_OSES,
    )
