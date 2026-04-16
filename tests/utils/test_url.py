from cross_auth.utils._url import construct_relative_url


def test_simple_url_replacement():
    """Test replacing the last segment of a simple URL."""
    url = "http://example.com/auth/authorize"
    result = construct_relative_url(url, "callback")
    assert result == "http://example.com/auth/callback"


def test_url_with_port():
    """Test URL with port number."""
    url = "http://example.com:8080/api/authorize"
    result = construct_relative_url(url, "callback")
    assert result == "http://example.com:8080/api/callback"


def test_nested_path():
    """Test URL with nested paths."""
    url = "http://example.com/api/v1/auth/provider/authorize"
    result = construct_relative_url(url, "callback")
    assert result == "http://example.com/api/v1/auth/provider/callback"


def test_url_with_trailing_slash():
    """Test URL that ends with a trailing slash."""
    url = "http://example.com/auth/authorize/"
    result = construct_relative_url(url, "callback")
    assert result == "http://example.com/auth/callback"


def test_https_url():
    """Test HTTPS URL."""
    url = "https://secure.example.com/oauth/authorize"
    result = construct_relative_url(url, "callback")
    assert result == "https://secure.example.com/oauth/callback"


def test_url_with_query_params():
    """Test that query parameters are not affected."""
    url = "http://example.com/auth/authorize?foo=bar"
    result = construct_relative_url(url, "callback")
    assert result == "http://example.com/auth/callback"


def test_root_path():
    """Test URL with root path."""
    url = "http://example.com/authorize"
    result = construct_relative_url(url, "callback")
    assert result == "http://example.com/callback"


def test_with_base_url_simple():
    """Test with base_url provided - simple case."""
    url = "http://internal:8000/auth/authorize"
    base_url = "http://public.com"
    result = construct_relative_url(url, "callback", base_url)
    assert result == "http://public.com/auth/callback"


def test_with_base_url_and_port():
    """Test with base_url that has a port."""
    url = "http://backend:8080/api/auth/authorize"
    base_url = "https://api.example.com:9000"
    result = construct_relative_url(url, "callback", base_url)
    assert result == "https://api.example.com:9000/api/auth/callback"


def test_with_base_url_trailing_slash():
    """Test with base_url that has a trailing slash."""
    url = "http://internal/auth/provider/authorize"
    base_url = "http://public.com/"
    result = construct_relative_url(url, "callback", base_url)
    assert result == "http://public.com/auth/provider/callback"


def test_with_base_url_nested_path():
    """Test with base_url and deeply nested paths."""
    url = "http://internal/api/v1/auth/oauth/provider/authorize"
    base_url = "https://api.example.com"
    result = construct_relative_url(url, "callback", base_url)
    assert result == "https://api.example.com/api/v1/auth/oauth/provider/callback"


def test_with_base_url_root_path():
    """Test with base_url when the path is at root."""
    url = "http://internal/authorize"
    base_url = "http://example.com"
    result = construct_relative_url(url, "callback", base_url)
    assert result == "http://example.com/callback"


def test_different_segments():
    """Test replacing with different segment names."""
    url = "http://example.com/oauth/start"

    result1 = construct_relative_url(url, "complete")
    assert result1 == "http://example.com/oauth/complete"

    result2 = construct_relative_url(url, "cancel")
    assert result2 == "http://example.com/oauth/cancel"

    result3 = construct_relative_url(url, "refresh")
    assert result3 == "http://example.com/oauth/refresh"


def test_edge_case_double_slash():
    """Test that double slashes are preserved in the path if they exist in the original URL."""
    url = "http://example.com/auth//authorize"
    base_url = "http://public.com"
    result = construct_relative_url(url, "callback", base_url)
    # The function preserves the path structure including double slashes
    assert result == "http://public.com/auth//callback"


def test_edge_case_empty_path_segment():
    """Test with empty path segments."""
    url = "http://example.com//auth//authorize"
    result = construct_relative_url(url, "callback")
    assert result == "http://example.com//auth//callback"


def test_base_url_overrides_completely():
    """Test that base_url completely overrides the original URL's scheme and host."""
    url = "http://internal:8080/secure/endpoint"
    base_url = "https://external.api.com"
    result = construct_relative_url(url, "callback", base_url)
    assert result == "https://external.api.com/secure/callback"
    assert "internal" not in result
    assert "8080" not in result
    assert result.startswith("https://")
