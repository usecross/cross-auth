from urllib.parse import urlparse, urlunparse


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
    parsed_url = urlparse(url)

    path_parts = parsed_url.path.rstrip("/").split("/")
    if path_parts and path_parts[-1]:
        path_parts.pop()
    new_path = "/".join(path_parts + [new_segment])

    if base_url:
        parsed_base = urlparse(base_url.rstrip("/"))
        base_path = parsed_base.path.rstrip("/")
        combined_path = f"{base_path}{new_path}" if base_path else new_path
        return urlunparse(
            (
                parsed_base.scheme,
                parsed_base.netloc,
                combined_path,
                "",
                "",
                "",
            )
        )

    return urlunparse(
        (
            parsed_url.scheme,
            parsed_url.netloc,
            new_path,
            "",
            "",
            "",
        )
    )
