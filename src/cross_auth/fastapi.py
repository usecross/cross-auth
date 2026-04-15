from __future__ import annotations

import secrets
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from cross_web import AsyncHTTPRequest, Cookie
from fastapi import HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import AwareDatetime, BaseModel, ValidationError

from ._config import Config
from ._context import AccountsStorage, Context, SecondaryStorage, User
from ._password import authenticate as _authenticate
from ._session import (
    SessionConfig,
    resolve_config,
)
from ._session import (
    create_session as _create_session,
)
from ._session import (
    delete_session as _delete_session,
)
from ._session import (
    get_current_user as _get_current_user_from_session,
)
from ._session import (
    make_clear_cookie as _make_clear_cookie,
)
from ._session import (
    make_session_cookie as _make_session_cookie,
)
from .router import AuthRouter
from .social_providers.oauth import (
    OAuth2AuthorizationRequestData,
    OAuth2Provider,
    OAuth2ProviderCallbackError,
)
from .utils._pkce import calculate_s256_challenge, generate_code_verifier

# TODO: if we add more framework integrations, extract shared storage/session
# logic into a private _BaseCrossAuth class that framework classes inherit from.

_SESSION_SOCIAL_LOGIN_STATE_PREFIX = "oauth:session_social_login:"
_SESSION_SOCIAL_LOGIN_MAX_AGE = 600


class SessionSocialLoginState(BaseModel):
    provider_name: str
    next_url: str
    expires_at: AwareDatetime

    @property
    def is_expired(self) -> bool:
        return datetime.now(tz=timezone.utc) > self.expires_at


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

        self._router = AuthRouter(
            providers=providers,
            secondary_storage=storage,
            accounts_storage=accounts_storage,
            get_user_from_request=self._get_user_from_request,
            create_token=create_token,
            trusted_origins=trusted_origins,
            base_url=base_url,
            config=config,
        )
        self._add_session_social_login_routes(providers)

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

    def _make_context(self) -> Context:
        return Context(
            secondary_storage=self._storage,
            accounts_storage=self._accounts_storage,
            create_token=self._create_token,
            trusted_origins=self._trusted_origins,
            get_user_from_request=self._get_user_from_request,
            base_url=self._base_url,
            config=self._config,
        )

    def _resolve_user(self, request: Request) -> User | None:
        async_request = AsyncHTTPRequest.from_fastapi(request)
        return self._get_user_from_request(async_request)

    def _default_post_login_redirect_url(self) -> str:
        return self._config.get("default_post_login_redirect_url") or "/"

    def _login_url(self) -> str:
        return self._config.get("login_url") or "/login"

    def _append_query_params(self, url: str, **params: str | None) -> str:
        parsed = urlparse(url)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))

        for key, value in params.items():
            if value is not None:
                query[key] = value

        return urlunparse(parsed._replace(query=urlencode(query)))

    def _redirect_to_login(self, error: str) -> RedirectResponse:
        return RedirectResponse(
            self._append_query_params(self._login_url(), error=error),
            status_code=302,
        )

    def _normalize_social_login_error(self, error: str) -> str:
        if error == "server_error":
            return "oauth_failed"
        return error

    def _normalize_next_url(self, request: Request, raw_next: str | None) -> str:
        fallback = self._default_post_login_redirect_url()

        if not raw_next:
            return fallback

        if raw_next.startswith("/") and not raw_next.startswith("//"):
            return raw_next

        parsed = urlparse(raw_next)

        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return fallback

        expected_host = (
            urlparse(self._base_url).netloc if self._base_url else request.url.netloc
        )

        if parsed.netloc != expected_host:
            return fallback

        return raw_next

    def _replace_request_path_suffix(
        self,
        request: Request,
        *,
        old_suffix: str,
        new_suffix: str,
    ) -> str:
        parsed = urlparse(str(request.url))
        path = parsed.path

        if not path.endswith(old_suffix):
            raise ValueError(
                f"Expected request path to end with {old_suffix!r}, got {path!r}"
            )

        new_path = f"{path[: -len(old_suffix)]}{new_suffix}"

        if self._base_url:
            return f"{self._base_url.rstrip('/')}{new_path}"

        return urlunparse((parsed.scheme, parsed.netloc, new_path, "", "", ""))

    def _make_session_social_login_start_endpoint(
        self, provider: OAuth2Provider
    ) -> Callable[[Request], RedirectResponse]:
        def session_social_login_start(request: Request) -> RedirectResponse:
            provider_state = secrets.token_hex(16)
            session_state = secrets.token_hex(16)
            next_url = self._normalize_next_url(
                request, request.query_params.get("next")
            )
            login_hint = request.query_params.get("login_hint")
            session_callback_url = self._replace_request_path_suffix(
                request,
                old_suffix=f"/{provider.id}/session/authorize",
                new_suffix=f"/{provider.id}/session/callback",
            )

            unused_code_challenge = calculate_s256_challenge(generate_code_verifier())

            provider_code_verifier: str | None = None
            provider_code_challenge: str | None = None
            provider_code_challenge_method: str | None = None

            if provider.supports_pkce:
                provider_code_verifier = generate_code_verifier()
                provider_code_challenge = calculate_s256_challenge(
                    provider_code_verifier
                )
                provider_code_challenge_method = "S256"

            self._storage.set(
                f"{_SESSION_SOCIAL_LOGIN_STATE_PREFIX}{session_state}",
                SessionSocialLoginState(
                    provider_name=provider.id,
                    next_url=next_url,
                    expires_at=datetime.now(tz=timezone.utc)
                    + timedelta(seconds=_SESSION_SOCIAL_LOGIN_MAX_AGE),
                ).model_dump_json(),
                ttl=_SESSION_SOCIAL_LOGIN_MAX_AGE,
            )

            self._storage.set(
                f"oauth:authorization_request:{provider_state}",
                OAuth2AuthorizationRequestData(
                    client_id="__cross_auth_session__",
                    redirect_uri=session_callback_url,
                    login_hint=login_hint,
                    client_state=session_state,
                    state=provider_state,
                    code_challenge=unused_code_challenge,
                    code_challenge_method="S256",
                    link=False,
                    user_id=None,
                    provider_code_verifier=provider_code_verifier,
                ).model_dump_json(),
                ttl=_SESSION_SOCIAL_LOGIN_MAX_AGE,
            )

            query_params = provider.build_authorization_params(
                state=provider_state,
                proxy_redirect_uri=session_callback_url,
                response_type="code",
                code_challenge=provider_code_challenge,
                code_challenge_method=provider_code_challenge_method,
                login_hint=login_hint,
            )
            authorization_url = (
                f"{provider.authorization_endpoint}?{urlencode(query_params)}"
            )

            return RedirectResponse(authorization_url, status_code=302)

        return session_social_login_start

    def _restore_session_social_login_state(
        self,
        provider_data: OAuth2AuthorizationRequestData,
        *,
        provider_name: str,
    ) -> SessionSocialLoginState | None:
        if provider_data.client_state is None:
            return None

        raw_session_state = self._storage.pop(
            f"{_SESSION_SOCIAL_LOGIN_STATE_PREFIX}{provider_data.client_state}"
        )

        if raw_session_state is None:
            return None

        try:
            session_state = SessionSocialLoginState.model_validate_json(
                raw_session_state
            )
        except ValidationError:
            return None

        if session_state.is_expired or session_state.provider_name != provider_name:
            return None

        return session_state

    def _make_session_social_login_callback_endpoint(
        self, provider: OAuth2Provider
    ) -> Callable[[Request], Awaitable[RedirectResponse]]:
        async def session_social_login_callback(request: Request) -> RedirectResponse:
            async_request = AsyncHTTPRequest.from_fastapi(request)
            context = self._make_context()

            try:
                result = await provider._complete_provider_callback_to_user(
                    async_request,
                    context,
                )
            except OAuth2ProviderCallbackError as e:
                error = (
                    "invalid_state"
                    if e.error == "invalid_state"
                    else self._normalize_social_login_error(e.error)
                )
                return self._redirect_to_login(error)

            session_state = self._restore_session_social_login_state(
                result.provider_data,
                provider_name=provider.id,
            )
            if session_state is None:
                return self._redirect_to_login("invalid_state")

            response = RedirectResponse(session_state.next_url, status_code=302)
            self.login(str(result.user.id), response=response)
            return response

        return session_social_login_callback

    def _add_session_social_login_routes(self, providers: list[OAuth2Provider]) -> None:
        for provider in providers:
            self._router.add_api_route(
                f"/{provider.id}/session/authorize",
                self._make_session_social_login_start_endpoint(provider),
                methods=["GET"],
                summary=f"Start {provider.id} social login with a browser session",
                operation_id=f"{provider.id}_session_authorize",
                name=f"{provider.id}_session_authorize",
            )
            self._router.add_api_route(
                f"/{provider.id}/session/callback",
                self._make_session_social_login_callback_endpoint(provider),
                methods=["GET", "POST"],
                summary=f"Finish {provider.id} social login with a browser session",
                operation_id=f"{provider.id}_session_callback",
                name=f"{provider.id}_session_callback",
            )

    def get_current_user(self, request: Request) -> User | None:
        return self._resolve_user(request)

    def require_current_user(self, request: Request) -> User:
        user = self._resolve_user(request)
        if user is None:
            raise HTTPException(status_code=401)
        return user

    def authenticate(self, email: str, password: str) -> User | None:
        return _authenticate(email, password, self._accounts_storage)

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

    def login(self, user_id: str, *, response: Response) -> None:
        resolved = resolve_config(self._session_config)
        max_age = resolved["max_age"]
        session_id, _ = _create_session(user_id, self._storage, max_age=max_age)
        cookie = _make_session_cookie(session_id, self._session_config)
        self._set_cookie_on_response(response, cookie)

    def logout(self, request: Request, *, response: Response) -> None:
        resolved = resolve_config(self._session_config)
        cookie_name = resolved["cookie_name"]
        session_id = request.cookies.get(cookie_name)
        if session_id is not None:
            _delete_session(session_id, self._storage)
        cookie = _make_clear_cookie(self._session_config)
        self._set_cookie_on_response(response, cookie)
