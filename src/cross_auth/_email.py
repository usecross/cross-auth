def normalize_email(email: str) -> str:
    """Default email normalization: trim surrounding whitespace and lowercase.

    Cross-Auth applies this before every user lookup or creation by email, so
    ``Alice@Example.com`` and ``alice@example.com`` resolve to the same
    account. Pass ``normalize_email=`` to ``CrossAuth`` to replace it — e.g.
    to also collapse Gmail dot-aliases — ideally composing with this default.
    Provider-reported emails stored on social accounts (``provider_email``)
    are kept raw.
    """
    return email.strip().lower()
