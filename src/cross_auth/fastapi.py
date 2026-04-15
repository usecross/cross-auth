from __future__ import annotations

from collections.abc import Callable

from cross_web import AsyncHTTPRequest, Cookie
from fastapi import HTTPException, Request, Response

from ._config import Config
from ._context import AccountsStorage, SecondaryStorage, User
from ._password import authenticate as _authenticate
from ._session import (
    SessionConfig,
    create_session as _create_session,
    delete_session as _delete_session,
    get_current_user as _get_current_user_from_session,
    make_clear_cookie as _make_clear_cookie,
    make_session_cookie as _make_session_cookie,
    resolve_config,
)
from .router import AuthRouter
from .social_providers.oauth import OAuth2Provider
from .utils._response import Response as CrossAuthResponse

# TODO: if we add more framework integrations, extract shared storage/session
# logic into a private _BaseCrossAuth class that framework classes inherit from.


class CrossAuth:
    def __init__(
        self,
        *,
        providers: list[OAuth2Provider],
        storage: SecondaryStorage,
        accounts_storage: AccountsStorage,
        create_token: Callable[[str], tuple[str, int]],
        trusted_origins: list[str],
        session_config: SessionConfig | None = None,
        get_user_from_request: Callable[[AsyncHTTPRequest], User | None] | None = None,
        base_url: str | None = None,
        config: Config | None = None,
    ):
        self._storage = storage
        self._accounts_storage = accounts_storage
        self._session_config = session_config
        self._create_token = create_token
        self._trusted_origins = trusted_origins
        self._base_url = base_url
        self._config: Config = config if config is not None else {}

        self._get_user_from_request = (
            get_user_from_request or self._default_get_user_from_request
        )

        provider_ids = {provider.id for provider in providers}
        if len(provider_ids) != len(providers):
            raise ValueError("Provider ids must be unique")

        self._router = AuthRouter(
            providers=providers,
            secondary_storage=storage,
            accounts_storage=accounts_storage,
            get_user_from_request=self._get_user_from_request,
            create_token=create_token,
            trusted_origins=trusted_origins,
            base_url=base_url,
            config=config,
            build_session_login_response=self._build_session_login_response,
        )

    @property
    def router(self) -> AuthRouter:
        return self._router

    def _default_get_user_from_request(self, request: AsyncHTTPRequest) -> User | None:
        return _get_current_user_from_session(
            request,
            self._storage,
            self._accounts_storage,
            self._session_config,
        )

    def _resolve_user(self, request: Request) -> User | None:
        async_request = AsyncHTTPRequest.from_fastapi(request)
        return self._get_user_from_request(async_request)

    def _set_cookie_on_response(self, response: Response, cookie: Cookie) -> None:
        response.set_cookie(
            key=cookie.name,
            value=cookie.value,
            max_age=cookie.max_age,
            path=cookie.path or "/",
            domain=cookie.domain,
            secure=cookie.secure,
            httponly=cookie.httponly,
            samesite=cookie.samesite,
        )

    def _create_session_cookie(self, user_id: str) -> Cookie:
        resolved = resolve_config(self._session_config)
        max_age = resolved["max_age"]
        session_id, _ = _create_session(user_id, self._storage, max_age=max_age)
        return _make_session_cookie(session_id, self._session_config)

    def _build_session_login_response(
        self, user_id: str, redirect_url: str
    ) -> CrossAuthResponse:
        cookie = self._create_session_cookie(user_id)
        return CrossAuthResponse.redirect(redirect_url, cookies=[cookie])

    def get_current_user(self, request: Request) -> User | None:
        return self._resolve_user(request)

    def require_current_user(self, request: Request) -> User:
        user = self._resolve_user(request)
        if user is None:
            raise HTTPException(status_code=401)
        return user

    def authenticate(self, email: str, password: str) -> User | None:
        return _authenticate(email, password, self._accounts_storage)

    def login(self, user_id: str, *, response: Response) -> None:
        cookie = self._create_session_cookie(user_id)
        self._set_cookie_on_response(response, cookie)

    def logout(self, request: Request, *, response: Response) -> None:
        resolved = resolve_config(self._session_config)
        cookie_name = resolved["cookie_name"]
        session_id = request.cookies.get(cookie_name)
        if session_id is not None:
            _delete_session(session_id, self._storage)
        cookie = _make_clear_cookie(self._session_config)
        self._set_cookie_on_response(response, cookie)
