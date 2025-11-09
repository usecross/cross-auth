def is_same_host(host: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        return host.endswith(pattern[1:])
    else:
        return host == pattern
