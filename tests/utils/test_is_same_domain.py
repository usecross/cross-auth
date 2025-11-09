from cross_auth.utils._is_same_host import is_same_host


def test_is_same_host():
    assert is_same_host("example.com", "example.com")
    assert is_same_host("sub.example.com", "*.example.com")
    assert not is_same_host("sub.example.com", "example.com")
    assert not is_same_host("example.com", "some.other.domain.com")
