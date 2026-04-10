from __future__ import annotations

import inspect
import logging
from collections.abc import Mapping

from cross_web import AsyncHTTPRequest

from ._context import Context
from ._route import Route
from ._storage import SocialAccount, User
from .utils._response import Response

logger = logging.getLogger(__name__)


def _get_social_account_id(request: AsyncHTTPRequest) -> str | None:
    path_params = getattr(request, "path_params", None)
    if isinstance(path_params, Mapping):
        social_account_id = path_params.get("social_account_id")
        if isinstance(social_account_id, str):
            return social_account_id

    return None


def _find_social_account(user: User, social_account_id: str) -> SocialAccount | None:
    return next(
        (
            social_account
            for social_account in user.social_accounts
            if str(social_account.id) == social_account_id
        ),
        None,
    )


def _has_alternative_login_method(
    user: User, current_social_account: SocialAccount
) -> bool:
    if bool(user.hashed_password):
        return True

    return any(
        social_account.id != current_social_account.id and social_account.is_login_method
        for social_account in user.social_accounts
    )


async def _run_on_social_account_unlinked(
    request: AsyncHTTPRequest,
    context: Context,
    user: User,
    social_account: SocialAccount,
) -> None:
    hook = context.on_social_account_unlinked

    if hook is None:
        return

    try:
        result = hook(request, context, user, social_account)

        if inspect.isawaitable(result):
            await result
    except Exception:
        logger.exception(
            "Post-unlink hook failed for provider=%s user_id=%s",
            social_account.provider,
            user.id,
        )


async def unlink_social_account(request: AsyncHTTPRequest, context: Context) -> Response:
    user = context.get_user_from_request(request)

    if user is None:
        return Response.error(
            "unauthorized",
            error_description="Not logged in",
            status_code=401,
        )

    social_account_id = _get_social_account_id(request)
    if social_account_id is None:
        return Response.error(
            "server_error",
            error_description="Missing social account id",
            status_code=500,
        )

    social_account = _find_social_account(user, social_account_id)

    if social_account is None:
        return Response.error(
            "account_not_linked",
            error_description="Social account not found",
            status_code=404,
        )

    if social_account.is_login_method and not _has_alternative_login_method(
        user, social_account
    ):
        return Response.error(
            "last_login_method",
            error_description="Cannot unlink the only remaining login method",
        )

    context.accounts_storage.delete_social_account(social_account.id)
    await _run_on_social_account_unlinked(request, context, user, social_account)

    return Response(
        status_code=200,
        body='{"message": "Account unlinked"}',
        headers={"Content-Type": "application/json"},
    )


def routes() -> list[Route]:
    return [
        Route(
            path="/social-accounts/{social_account_id}",
            methods=["DELETE"],
            function=unlink_social_account,
            operation_id="unlink_social_account",
            summary="Unlink social account",
            openapi={
                "parameters": [
                    {
                        "name": "social_account_id",
                        "in": "path",
                        "required": True,
                        "description": "The linked social account id to unlink",
                        "schema": {"type": "string"},
                    }
                ]
            },
        )
    ]
