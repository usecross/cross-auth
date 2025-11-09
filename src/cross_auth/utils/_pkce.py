import base64
import hashlib
import secrets


def generate_code_verifier() -> str:
    """Generate a PKCE code verifier (43-128 characters)."""
    return (
        base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
    )


def calculate_s256_challenge(verifier: str) -> str:
    sha256_digest = hashlib.sha256(verifier.encode("ascii")).digest()

    challenge = base64.urlsafe_b64encode(sha256_digest).rstrip(b"=").decode("ascii")

    return challenge


def validate_pkce(
    stored_challenge: str, stored_method: str, received_verifier: str
) -> bool:
    if stored_method != "S256":
        raise ValueError("Unsupported code challenge method")

    calculated_challenge = calculate_s256_challenge(received_verifier)

    return secrets.compare_digest(calculated_challenge, stored_challenge)
