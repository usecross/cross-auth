"""The FastAPI router's two-factor routes, over the shared handlers."""

from __future__ import annotations

from functools import partial
from typing import Any

from ._mfa_flow import (
    CrossAuthSessions,
    confirm_handler,
    enroll_handler,
    reauthenticate_handler,
    recovery_codes_handler,
    remove_handler,
    status_handler,
    verify_handler,
)
from ._route import Route

_SESSIONS = CrossAuthSessions()


def _responses(descriptions: dict[str, str]) -> dict[str, Any]:
    return {
        "responses": {
            status: {"description": description}
            for status, description in descriptions.items()
        }
    }


_CHANGE_ERRORS = {
    "401": "Not logged in",
    "403": "reauthentication_required: sign in or reauthenticate first",
}


def mfa_routes() -> list[Route]:
    return [
        Route(
            path="/mfa",
            methods=["GET"],
            function=partial(status_handler, sessions=_SESSIONS),
            operation_id="get_mfa_status",
            summary="The caller's two-factor authentication status",
            openapi=_responses({"401": "Not logged in"}),
        ),
        Route(
            path="/reauthenticate",
            methods=["POST"],
            function=partial(reauthenticate_handler, sessions=_SESSIONS),
            operation_id="reauthenticate",
            summary="Confirm the caller's identity before changing 2FA",
            read_body=True,
            openapi=_responses(
                {"400": "Wrong password or code", "401": "Not logged in"}
            ),
        ),
        Route(
            path="/mfa/totp/enroll",
            methods=["POST"],
            function=partial(enroll_handler, sessions=_SESSIONS),
            operation_id="start_totp_enrollment",
            summary="Start setting up an authenticator app",
            read_body=True,
            openapi=_responses(_CHANGE_ERRORS),
        ),
        Route(
            path="/mfa/totp/confirm",
            methods=["POST"],
            function=partial(confirm_handler, sessions=_SESSIONS),
            operation_id="confirm_totp_enrollment",
            summary="Confirm an authenticator app with its first code",
            status_code=201,
            read_body=True,
            openapi=_responses(
                {"400": "Wrong code or unknown enrollment", "401": "Not logged in"}
            ),
        ),
        Route(
            path="/mfa/recovery-codes",
            methods=["POST"],
            function=partial(recovery_codes_handler, sessions=_SESSIONS),
            operation_id="regenerate_recovery_codes",
            summary="Replace the caller's recovery codes",
            openapi=_responses(_CHANGE_ERRORS),
        ),
        Route(
            path="/mfa/factors/{factor_id}/remove",
            methods=["POST"],
            function=partial(remove_handler, sessions=_SESSIONS),
            operation_id="remove_mfa_factor",
            summary="Remove one of the caller's second factors",
            path_parameters=[
                {
                    "name": "factor_id",
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string", "title": "Factor Id"},
                }
            ],
            openapi=_responses({**_CHANGE_ERRORS, "404": "No such factor"}),
        ),
        Route(
            path="/mfa/verify",
            methods=["POST"],
            function=verify_handler,
            operation_id="verify_mfa",
            summary="Finish a sign-in with its second factor",
            read_body=True,
            openapi=_responses(
                {"400": "Wrong code or expired sign-in", "429": "Too many wrong codes"}
            ),
        ),
    ]
