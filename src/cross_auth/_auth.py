"""Email/password authentication module for cross-auth.

Provides endpoints for email/password authentication:
- POST /signup - Create account with email/password
- POST /login - Authenticate with email/password
- POST /logout - Clear session

Supports dual response strategy: session cookie (default) OR bearer token.
"""

import json
import logging
from datetime import datetime, timedelta, timezone

from cross_web import AsyncHTTPRequest
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, ValidationError

from ._context import Context
from ._route import Route
from .utils._response import Response

logger = logging.getLogger(__name__)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Pre-computed dummy hash for constant-time password verification
# This prevents timing attacks that could enumerate valid users
DUMMY_PASSWORD_HASH = "$2b$12$K6qGJzUzL5H0yQKqVZKZFuJ9aZqZ5qH0yQKqVZKZFuJ9aZqZ5qH0y"


class SignupRequest(BaseModel):
    """Request body for signup endpoint."""

    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    """Request body for login endpoint."""

    email: EmailStr
    password: str


class AuthManager:
    """Manager for email/password authentication routes."""

    def __init__(self, enable_signup: bool = True):
        """Initialize the auth manager.

        Args:
            enable_signup: Whether to enable the signup endpoint.
                          Set to False to disable self-registration.
        """
        self.enable_signup = enable_signup

    def _hash_password(self, password: str) -> str:
        """Hash a password using bcrypt."""
        return pwd_context.hash(password)

    def _verify_password(
        self, plain_password: str, hashed_password: str | None
    ) -> bool:
        """Verify a password against a hash.

        Uses constant-time comparison to prevent timing attacks.
        """
        if hashed_password is None:
            # Always verify against dummy hash to prevent timing attacks
            pwd_context.verify(plain_password, DUMMY_PASSWORD_HASH)
            return False
        return pwd_context.verify(plain_password, hashed_password)

    def _get_client_info(
        self, request: AsyncHTTPRequest
    ) -> tuple[str | None, str | None]:
        """Extract IP address and user agent from request."""
        # Try common headers for proxied requests
        ip_address = (
            request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or request.headers.get("X-Real-IP")
            or None
        )
        user_agent = request.headers.get("User-Agent")
        return ip_address, user_agent

    def _create_session_response(
        self,
        user_id: str,
        email: str,
        email_verified: bool,
        context: Context,
        request: AsyncHTTPRequest,
    ) -> Response:
        """Create a response with session cookie."""
        if not context.session_storage:
            return Response.error(
                "session_not_enabled",
                error_description="Session-based authentication is not enabled",
                status_code=500,
            )

        expires_in = int(context.get_session_config("expires_in") or 604800)
        expires_at = datetime.now(tz=timezone.utc) + timedelta(seconds=expires_in)

        ip_address, user_agent = self._get_client_info(request)

        session = context.session_storage.create_session(
            user_id=user_id,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        cookie = context.create_session_cookie(session)

        response_data = {
            "user": {
                "id": user_id,
                "email": email,
                "email_verified": email_verified,
            },
        }

        return Response(
            status_code=200,
            body=json.dumps(response_data),
            headers={
                "Content-Type": "application/json",
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
            },
            cookies=[cookie],
        )

    def _create_token_response(
        self, user_id: str, email: str, email_verified: bool, context: Context
    ) -> Response:
        """Create a response with bearer token."""
        token, expires_in = context.create_token(user_id)

        response_data = {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": expires_in,
            "user": {
                "id": user_id,
                "email": email,
                "email_verified": email_verified,
            },
        }

        return Response(
            status_code=200,
            body=json.dumps(response_data),
            headers={
                "Content-Type": "application/json",
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
            },
        )

    async def signup(self, request: AsyncHTTPRequest, context: Context) -> Response:
        """Create a new user account with email and password.

        Request body:
            - email: User's email address
            - password: User's password

        Query params:
            - response_type: "session" (default) or "token"

        Returns:
            - On success: User info + session cookie OR access token
            - On failure: Error response
        """
        if not self.enable_signup:
            return Response.error(
                "signup_disabled",
                error_description="Signup is disabled",
                status_code=403,
            )

        try:
            body = await request.get_body()
            signup_data = SignupRequest.model_validate_json(body)
        except ValidationError as e:
            logger.warning("Invalid signup request: %s", e)
            return Response.error(
                "invalid_request",
                error_description="Invalid request body",
                status_code=400,
            )

        # Check if user already exists
        existing_user = context.accounts_storage.find_user_by_email(signup_data.email)
        if existing_user:
            return Response.error(
                "user_exists",
                error_description="A user with this email already exists",
                status_code=409,
            )

        # Hash password and create user
        hashed_password = self._hash_password(signup_data.password)

        try:
            user = context.accounts_storage.create_user_with_password(
                email=signup_data.email,
                hashed_password=hashed_password,
                email_verified=False,
                user_info={"email": signup_data.email},
            )
        except Exception as e:
            logger.error("Failed to create user: %s", e)
            return Response.error(
                "server_error",
                error_description="Failed to create user",
                status_code=500,
            )

        # Determine response type
        response_type = request.query_params.get("response_type", "session")

        if response_type == "token":
            return self._create_token_response(
                str(user.id), user.email, user.email_verified, context
            )
        else:
            # Default to session
            if context.session_enabled:
                return self._create_session_response(
                    str(user.id), user.email, user.email_verified, context, request
                )
            else:
                # Fall back to token if sessions not enabled
                return self._create_token_response(
                    str(user.id), user.email, user.email_verified, context
                )

    async def login(self, request: AsyncHTTPRequest, context: Context) -> Response:
        """Authenticate with email and password.

        Request body:
            - email: User's email address
            - password: User's password

        Query params:
            - response_type: "session" (default) or "token"

        Returns:
            - On success: User info + session cookie OR access token
            - On failure: Error response
        """
        try:
            body = await request.get_body()
            login_data = LoginRequest.model_validate_json(body)
        except ValidationError as e:
            logger.warning("Invalid login request: %s", e)
            return Response.error(
                "invalid_request",
                error_description="Invalid request body",
                status_code=400,
            )

        # Find user
        user = context.accounts_storage.find_user_by_email(login_data.email)

        # Always perform password verification to prevent timing attacks
        password_valid = self._verify_password(
            login_data.password,
            user.hashed_password if user else None,
        )

        if not user or not password_valid:
            return Response.error(
                "invalid_credentials",
                error_description="Invalid email or password",
                status_code=401,
            )

        # Determine response type
        response_type = request.query_params.get("response_type", "session")

        if response_type == "token":
            return self._create_token_response(
                str(user.id), user.email, user.email_verified, context
            )
        else:
            # Default to session
            if context.session_enabled:
                return self._create_session_response(
                    str(user.id), user.email, user.email_verified, context, request
                )
            else:
                # Fall back to token if sessions not enabled
                return self._create_token_response(
                    str(user.id), user.email, user.email_verified, context
                )

    async def logout(self, request: AsyncHTTPRequest, context: Context) -> Response:
        """Logout by clearing the session cookie.

        This is an alias for DELETE /session but as a POST endpoint
        for easier form submission.
        """
        if not context.session_enabled or not context.session_storage:
            # If sessions not enabled, just return success
            # (client might be using token-based auth)
            return Response(
                status_code=200,
                body=json.dumps({"message": "Logged out"}),
                headers={"Content-Type": "application/json"},
            )

        session = context.get_session_from_request(request)

        if session:
            context.session_storage.delete_session(session.id)

        # Always return logout cookie to clear the session on client
        logout_cookie = context.create_logout_cookie()

        return Response(
            status_code=200,
            body=json.dumps({"message": "Logged out"}),
            headers={"Content-Type": "application/json"},
            cookies=[logout_cookie],
        )

    @property
    def routes(self) -> list[Route]:
        """Return the auth routes."""
        routes = [
            Route(
                path="/login",
                methods=["POST"],
                function=self.login,
                operation_id="login",
                summary="Login with email and password",
            ),
            Route(
                path="/logout",
                methods=["POST"],
                function=self.logout,
                operation_id="logout",
                summary="Logout",
            ),
        ]

        if self.enable_signup:
            routes.insert(
                0,
                Route(
                    path="/signup",
                    methods=["POST"],
                    function=self.signup,
                    operation_id="signup",
                    summary="Create account with email and password",
                ),
            )

        return routes
