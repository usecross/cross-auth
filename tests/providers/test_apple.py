import json
import time
from typing import cast

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import RSAAlgorithm

from cross_auth.social_providers.apple import (
    AppleAuthConfig,
    AppleIdTokenPayload,
    AppleProvider,
)
from cross_auth.social_providers.oauth import (
    OAuth2Exception,
    UserInfo,
    ValidatedUserInfo,
)

# --- Fixtures ---


@pytest.fixture
def apple_private_key() -> str:
    """Generate a test ES256 private key."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


@pytest.fixture
def apple_config(apple_private_key: str) -> AppleAuthConfig:
    """Create test Apple configuration."""
    return AppleAuthConfig(
        client_id="com.example.test",
        team_id="TEAM123456",
        key_id="KEY123ABC",
        private_key=apple_private_key,
    )


@pytest.fixture
def apple_provider(apple_config: AppleAuthConfig) -> AppleProvider:
    """Create test Apple provider."""
    return AppleProvider(config=apple_config)


@pytest.fixture
def mock_apple_jwks():
    """Generate mock Apple JWKS for testing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    jwk = json.loads(RSAAlgorithm.to_jwk(public_key))
    jwk["kid"] = "test_kid"
    jwk["use"] = "sig"
    jwk["alg"] = "RS256"

    return {
        "keys": [jwk],
        "private_key": private_key,
    }


# --- AppleAuthConfig tests ---


def test_apple_auth_config_valid(apple_private_key: str):
    config = AppleAuthConfig(
        client_id="com.example.app",
        team_id="ABCD123456",
        key_id="XYZ789",
        private_key=apple_private_key,
    )
    assert config.client_id == "com.example.app"
    assert config.team_id == "ABCD123456"
    assert config.key_id == "XYZ789"


# --- Client secret generation tests ---


def test_generate_client_secret_structure(apple_provider: AppleProvider):
    """Test that client secret is a valid JWT with correct structure."""
    secret = apple_provider.generate_client_secret()

    # Should be a valid JWT
    assert secret.count(".") == 2

    # Decode without verification to check structure
    header = jwt.get_unverified_header(secret)
    assert header["alg"] == "ES256"
    assert header["kid"] == "KEY123ABC"

    payload = jwt.decode(secret, options={"verify_signature": False})
    assert payload["iss"] == "TEAM123456"
    assert payload["sub"] == "com.example.test"
    assert payload["aud"] == "https://appleid.apple.com"
    assert "iat" in payload
    assert "exp" in payload


def test_client_secret_expiration(apple_provider: AppleProvider):
    """Test that client secret has correct expiration (180 days)."""
    secret = apple_provider.generate_client_secret()
    payload = jwt.decode(secret, options={"verify_signature": False})

    now = int(time.time())
    expected_exp = now + (86400 * 180)  # 180 days

    # Allow 5 second tolerance
    assert abs(payload["exp"] - expected_exp) < 5


# --- Authorization params tests ---


def test_build_authorization_params_basic(apple_provider: AppleProvider):
    """Test basic authorization params."""
    params = apple_provider.build_authorization_params(
        state="test_state",
        proxy_redirect_uri="https://example.com/callback",
        response_type="code",
    )

    assert params["client_id"] == "com.example.test"
    assert params["redirect_uri"] == "https://example.com/callback"
    assert params["response_type"] == "code"
    assert params["scope"] == "name email"  # Space-separated
    assert params["state"] == "test_state"
    assert params["response_mode"] == "form_post"


def test_build_authorization_params_with_pkce(apple_provider: AppleProvider):
    """Test authorization params with PKCE."""
    params = apple_provider.build_authorization_params(
        state="test_state",
        proxy_redirect_uri="https://example.com/callback",
        response_type="code",
        code_challenge="test_challenge",
        code_challenge_method="S256",
    )

    assert params["code_challenge"] == "test_challenge"
    assert params["code_challenge_method"] == "S256"


def test_scope_is_space_separated(apple_provider: AppleProvider):
    """Test that scope uses space separator (not plus)."""
    params = apple_provider.build_authorization_params(
        state="test_state",
        proxy_redirect_uri="https://example.com/callback",
        response_type="code",
    )

    # Critical: must be space-separated, not "name+email"
    assert params["scope"] == "name email"
    assert "+" not in params["scope"]


# --- Token exchange params tests ---


def test_build_token_exchange_params(apple_provider: AppleProvider):
    """Test token exchange params include dynamic client_secret."""
    params = apple_provider.build_token_exchange_params(
        code="auth_code_123",
        redirect_uri="https://example.com/callback",
    )

    assert params["grant_type"] == "authorization_code"
    assert params["code"] == "auth_code_123"
    assert params["redirect_uri"] == "https://example.com/callback"
    assert params["client_id"] == "com.example.test"
    assert "client_secret" in params
    # Client secret should be a JWT
    assert params["client_secret"].count(".") == 2


def test_build_token_exchange_params_with_pkce(apple_provider: AppleProvider):
    """Test token exchange params with PKCE verifier."""
    params = apple_provider.build_token_exchange_params(
        code="auth_code_123",
        redirect_uri="https://example.com/callback",
        code_verifier="test_verifier",
    )

    assert params["code_verifier"] == "test_verifier"


# --- id_token validation tests ---


@pytest.fixture
def mock_secondary_storage(mock_apple_jwks: dict):
    """Create a mock secondary storage with Apple JWKS cached."""

    class MockStorage:
        def get(self, key: str) -> str | None:
            if key == "apple:jwks":
                return json.dumps({"keys": mock_apple_jwks["keys"]})
            return None

        def set(self, key: str, value: str, ttl: int | None = None) -> None:
            pass

        def delete(self, key: str) -> None:
            pass

    return MockStorage()


def test_validate_id_token_success(
    apple_provider: AppleProvider,
    mock_apple_jwks: dict,
    mock_secondary_storage,
):
    """Test successful id_token validation."""
    now = int(time.time())
    payload = {
        "iss": "https://appleid.apple.com",
        "sub": "001234.abcd5678.7890",
        "aud": "com.example.test",
        "iat": now,
        "exp": now + 3600,
        "email": "user@example.com",
        "email_verified": "true",
    }

    id_token = jwt.encode(
        payload,
        mock_apple_jwks["private_key"],
        algorithm="RS256",
        headers={"kid": "test_kid"},
    )

    claims = apple_provider.validate_id_token(id_token, mock_secondary_storage)

    assert claims["sub"] == "001234.abcd5678.7890"
    assert claims["email"] == "user@example.com"
    assert claims["email_verified"] == "true"


def test_validate_id_token_expired(
    apple_provider: AppleProvider,
    mock_apple_jwks: dict,
    mock_secondary_storage,
):
    """Test that expired id_token is rejected."""
    now = int(time.time())
    payload = {
        "iss": "https://appleid.apple.com",
        "sub": "001234.abcd5678.7890",
        "aud": "com.example.test",
        "iat": now - 7200,
        "exp": now - 3600,  # Expired 1 hour ago
    }

    id_token = jwt.encode(
        payload,
        mock_apple_jwks["private_key"],
        algorithm="RS256",
        headers={"kid": "test_kid"},
    )

    with pytest.raises(OAuth2Exception) as exc_info:
        apple_provider.validate_id_token(id_token, mock_secondary_storage)

    assert "expired" in exc_info.value.error_description.lower()


def test_validate_id_token_wrong_audience(
    apple_provider: AppleProvider,
    mock_apple_jwks: dict,
    mock_secondary_storage,
):
    """Test that id_token with wrong audience is rejected."""
    now = int(time.time())
    payload = {
        "iss": "https://appleid.apple.com",
        "sub": "001234.abcd5678.7890",
        "aud": "com.wrong.app",  # Wrong audience
        "iat": now,
        "exp": now + 3600,
    }

    id_token = jwt.encode(
        payload,
        mock_apple_jwks["private_key"],
        algorithm="RS256",
        headers={"kid": "test_kid"},
    )

    with pytest.raises(OAuth2Exception) as exc_info:
        apple_provider.validate_id_token(id_token, mock_secondary_storage)

    assert "audience" in exc_info.value.error_description.lower()


# --- User info extraction tests ---


def _make_payload(**kwargs) -> AppleIdTokenPayload:
    """Helper to create AppleIdTokenPayload with required fields."""
    defaults = {
        "iss": "https://appleid.apple.com",
        "aud": "com.example.test",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    return AppleIdTokenPayload.model_validate({**defaults, **kwargs})


def test_extract_user_info_basic(apple_provider: AppleProvider):
    """Test basic user info extraction from claims."""
    claims = _make_payload(
        sub="001234.abcd5678.7890",
        email="user@example.com",
        email_verified="true",  # Apple sends as string
    ).model_dump()

    user_info = apple_provider.extract_user_info_from_claims(claims)

    assert user_info["id"] == "001234.abcd5678.7890"
    assert user_info["email"] == "user@example.com"
    assert user_info["email_verified"] is True


def test_extract_user_info_private_relay(apple_provider: AppleProvider):
    """Test user info extraction with private relay email."""
    claims = _make_payload(
        sub="001234.abcd5678.7890",
        email="abc123@privaterelay.appleid.com",
        email_verified="true",
    ).model_dump()

    user_info = apple_provider.extract_user_info_from_claims(claims)

    assert user_info["email"] == "abc123@privaterelay.appleid.com"


def test_extract_user_info_without_extra(apple_provider: AppleProvider):
    """Test user info extraction with no extra data (typical login)."""
    claims = _make_payload(
        sub="001234.abcd5678.7890",
        email="user@example.com",
        email_verified="true",
    ).model_dump()

    user_info = apple_provider.extract_user_info_from_claims(claims)

    assert user_info["id"] == "001234.abcd5678.7890"
    assert user_info["email"] == "user@example.com"


# --- AppleIdTokenPayload parsing tests ---


def test_payload_parses_string_booleans():
    """Test that string booleans from Apple are parsed correctly."""
    payload = AppleIdTokenPayload.model_validate(
        {
            "iss": "https://appleid.apple.com",
            "sub": "user123",
            "aud": "com.example.app",
            "iat": 1234567890,
            "exp": 1234571490,
            "email_verified": "true",  # String, not bool
            "is_private_email": "false",  # String, not bool
        }
    )

    assert payload.email_verified is True
    assert payload.is_private_email is False


def test_payload_handles_actual_booleans():
    """Test that actual booleans also work (for flexibility)."""
    payload = AppleIdTokenPayload.model_validate(
        {
            "iss": "https://appleid.apple.com",
            "sub": "user123",
            "aud": "com.example.app",
            "iat": 1234567890,
            "exp": 1234571490,
            "email_verified": True,
            "is_private_email": False,
        }
    )

    assert payload.email_verified is True
    assert payload.is_private_email is False


def test_payload_defaults_missing_booleans_to_false():
    """Test that missing boolean fields default to False."""
    payload = AppleIdTokenPayload.model_validate(
        {
            "iss": "https://appleid.apple.com",
            "sub": "user123",
            "aud": "com.example.app",
            "iat": 1234567890,
            "exp": 1234571490,
        }
    )

    assert payload.email_verified is False
    assert payload.is_private_email is False


def test_payload_numeric_booleans_return_false():
    """Test that numeric values (non-bool, non-string) return False."""
    payload = AppleIdTokenPayload.model_validate(
        {
            "iss": "https://appleid.apple.com",
            "sub": "user123",
            "aud": "com.example.app",
            "iat": 1234567890,
            "exp": 1234571490,
            "email_verified": 1,
            "is_private_email": 0,
        }
    )

    assert payload.email_verified is False
    assert payload.is_private_email is False


@pytest.mark.parametrize(
    ("status_int", "expected"),
    [(0, "unsupported"), (1, "unknown"), (2, "likely_real")],
)
def test_payload_parses_real_user_status_integers(status_int: int, expected: str):
    """Test that integer real_user_status is parsed to descriptive string."""
    payload = AppleIdTokenPayload.model_validate(
        {
            "iss": "https://appleid.apple.com",
            "sub": "user123",
            "aud": "com.example.app",
            "iat": 1234567890,
            "exp": 1234571490,
            "real_user_status": status_int,
        }
    )
    assert payload.real_user_status == expected


def test_payload_real_user_status_defaults_to_none():
    """Test that missing real_user_status defaults to None."""
    payload = AppleIdTokenPayload.model_validate(
        {
            "iss": "https://appleid.apple.com",
            "sub": "user123",
            "aud": "com.example.app",
            "iat": 1234567890,
            "exp": 1234571490,
        }
    )

    assert payload.real_user_status is None


# --- Validate user info tests ---
# Apple uses the base class validate_user_info which requires both email and id.
# Email is always present in Apple's id_token when the email scope is requested.


def test_validate_user_info_with_email(apple_provider: AppleProvider):
    """Test validation with email present."""
    user_info: UserInfo = {
        "id": "001234.abcd5678.7890",
        "email": "user@example.com",
        "email_verified": True,
    }

    result = apple_provider.validate_user_info(user_info)

    assert isinstance(result, ValidatedUserInfo)
    assert result.email == "user@example.com"
    assert result.provider_user_id == "001234.abcd5678.7890"
    assert result.email_verified is True


def test_validate_user_info_missing_id(apple_provider: AppleProvider):
    """Test that missing user ID raises error."""
    user_info = cast(
        UserInfo,
        {
            "email": "user@example.com",
            "email_verified": None,
            # Missing id
        },
    )

    with pytest.raises(OAuth2Exception) as exc_info:
        apple_provider.validate_user_info(user_info)

    assert exc_info.value.error == "server_error"


# --- Routes tests ---


def test_routes_include_post_callback(apple_provider: AppleProvider):
    """Test that callback route accepts POST method."""
    routes = apple_provider.routes

    callback_route = next(r for r in routes if "callback" in r.path)

    assert "POST" in callback_route.methods
    assert "GET" in callback_route.methods  # Fallback


def test_routes_count(apple_provider: AppleProvider):
    """Test that all expected routes are registered."""
    routes = apple_provider.routes

    assert len(routes) == 4
    paths = [r.path for r in routes]
    assert "/apple/authorize" in paths
    assert "/apple/callback" in paths
    assert "/apple/finalize-link" in paths
    assert "/apple/link" in paths
