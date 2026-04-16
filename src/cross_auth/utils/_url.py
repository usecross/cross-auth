from urllib.parse import urlparse


def _replace_last_path_segment(url: str, new_segment: str) -> str:
    parsed_url = urlparse(url)
    path_parts = parsed_url.path.rstrip("/").split("/")

    if path_parts and path_parts[-1]:
        path_parts.pop()

    new_path = "/".join(path_parts + [new_segment])

    return parsed_url._replace(path=new_path, query="", fragment="").geturl()


def construct_relative_url(
    url: str, new_segment: str, base_url: str | None = None
) -> str:
    """
    Construct a relative URL by replacing the last segment of a URL path.

    If base_url is provided, it will be used as the base instead of the original URL.
    This is useful for scenarios where the internal request URL differs from the
    external-facing URL (e.g., Docker containers, reverse proxies).

    Args:
        url: The original URL
        new_segment: The new path segment to append
        base_url: Optional base URL to use instead of the original URL

    Returns:
        The constructed URL with the new segment
    """
    if base_url:
        # Remove trailing slash if present
        base = base_url.rstrip("/")

        # Parse the request URL to get the path
        parsed_url = urlparse(url)
        request_path = parsed_url.path

        # Get the directory path (remove the last segment)
        path_parts = request_path.rstrip("/").split("/")

        if path_parts and path_parts[-1]:  # Check if there's a last segment to remove
            path_parts.pop()  # Remove current endpoint (e.g., 'authorize')

        dir_path = "/".join(path_parts)

        return f"{base}{dir_path}/{new_segment}"
    else:
        return _replace_last_path_segment(url, new_segment)
