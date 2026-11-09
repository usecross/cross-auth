import string

import pytest

from cross_auth._token_format import generate_token, is_well_formed, validate_prefix

BASE62 = string.digits + string.ascii_uppercase + string.ascii_lowercase

# Tokens another consumer of this format already issues; they must keep
# validating byte for byte.
VECTORS = [
    ("fcd_0123456789ABCDEFGHIJKLMNOPQRSTUV2ltEVI", "fcd"),
    ("fcs_zyxwvutsrqponmlkjihgfedcbaZYXWVU29x7pD", "fcs"),
    ("fcd_000000000000000000000000000000001yDhEF", "fcd"),
    # The CRC32 here is under 62**5, so its checksum is padded with "0".
    ("fcd_111111111111111111111111111111110IrziY", "fcd"),
]


@pytest.mark.parametrize(("token", "prefix"), VECTORS)
def test_known_tokens_are_well_formed(token: str, prefix: str):
    assert is_well_formed(token, prefix)


@pytest.mark.parametrize(("token", "prefix"), VECTORS)
def test_any_single_character_change_is_rejected(token: str, prefix: str):
    for index, original in enumerate(token):
        for replacement in {"0", "a", "Z", "_", "-"} - {original}:
            tampered = token[:index] + replacement + token[index + 1 :]
            assert not is_well_formed(tampered, prefix), tampered


@pytest.mark.parametrize(
    "token",
    [
        pytest.param("fcd_0123456789ABCDEFGHIJKLMNOPQRSTUV2ltEV", id="short"),
        pytest.param("fcd_0123456789ABCDEFGHIJKLMNOPQRSTUV2ltEVIx", id="long"),
        pytest.param("fcd_0123456789ABCDEFGHIJKLMNOPQRSTUV2ltEVI\n", id="newline"),
        pytest.param("fcd_0123456789ABCDEFGHIJKLMNOPQRSTU-2ltEVI", id="dash"),
        pytest.param("fcd_0123456789ABCDEFGHIJKLMNOPQRSTU٢" + "2ltEVI", id="digit"),
        pytest.param("fcd0123456789ABCDEFGHIJKLMNOPQRSTUV2ltEVI", id="no-underscore"),
        pytest.param("", id="empty"),
    ],
)
def test_malformed_tokens_are_rejected(token: str):
    assert not is_well_formed(token, "fcd")


def test_wrong_prefix_is_rejected():
    assert not is_well_formed("fcd_0123456789ABCDEFGHIJKLMNOPQRSTUV2ltEVI", "fcs")
    assert not is_well_formed("fcd_0123456789ABCDEFGHIJKLMNOPQRSTUV2ltEVI", "fc")


def test_generated_tokens_are_well_formed():
    tokens = {generate_token("app") for _ in range(50)}

    assert len(tokens) == 50
    for token in tokens:
        assert token.startswith("app_")
        assert len(token) == len("app_") + 38
        assert set(token[len("app_") :]) <= set(BASE62)
        assert is_well_formed(token, "app")
        assert not is_well_formed(token, "other")


@pytest.mark.parametrize("prefix", ["a", "app", "fcd", "a1", "z" * 16])
def test_valid_prefixes(prefix: str):
    validate_prefix(prefix)


@pytest.mark.parametrize(
    "prefix",
    [
        "",
        "1app",
        "App",
        "my_app",
        "my-app",
        "a" * 17,
        "app\n",
        "äpp",
    ],
)
def test_invalid_prefixes_raise(prefix: str):
    with pytest.raises(ValueError, match="Invalid token prefix"):
        validate_prefix(prefix)

    with pytest.raises(ValueError, match="Invalid token prefix"):
        generate_token(prefix)
