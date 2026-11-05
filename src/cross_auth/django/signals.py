"""Signals sent around Cross Auth's provider sign-in, linking and disconnecting,
and around revoking sessions.

Connect receivers with ``@receiver`` in a module that your app's
``AppConfig.ready()`` imports. Each signal's sender is the user model, and
every receiver gets ``request`` (the view's ``HttpRequest``) besides the
arguments listed below. The provider flows' signals also get ``provider`` (the
provider ID, such as ``"google"``).

``before_*`` receivers get plain values: IDs are strings, and nothing is a
model instance. Raise ``PermissionDenied`` to refuse that step; Django answers
with its 403 response. Earlier committed changes remain: a first sign-in has
already created its user before ``before_login`` runs. Success signals follow
their completed state write, account commit or saved session; user and account
notifications carry native model instances.

Signals are sent with ``Signal.send()``: a receiver's exception propagates and
return values are ignored.

Apart from the session signals, they cover only Cross Auth's provider flows.
Django emits ``user_logged_in``
and ``user_logged_out`` through its native login and logout functions, including
password flows. Provider failures do not emit Django's ``user_login_failed``;
that signal belongs to failed calls to Django's ``authenticate()``.
"""

from django.dispatch import Signal

before_authorization = Signal()
"""Sent by the login and link views before they redirect to the provider.

Arguments: ``flow`` (``"login"`` or ``"link"``) and ``user_id``, the signed-in
user's for ``"link"`` and ``None`` for ``"login"``. Refusing stores no state.
"""

authorization_started = Signal()
"""Sent once the login or link view stored its state, before the redirect.

Arguments: ``flow``. For ``"link"``, ``request.user`` is the user linking.
"""

before_callback = Signal()
"""Sent when the provider's callback is verified, before any account is
looked up or written.

The state, browser binding, PKCE code exchange and ID token (signature,
audience, nonce) have all been checked. Arguments: ``flow``,
``provider_user_id``, ``email`` and ``email_verified`` as the provider
reported them, and ``user_id``, the linking user's for ``"link"`` and ``None``
for ``"login"``.
"""

before_user_create = Signal()
"""Sent before a first provider sign-in creates a user.

Arguments: ``email`` (normalized) and ``email_verified``. Nothing has been
written yet, so refusing here creates no user.
"""

user_created = Signal()
"""Sent once the new user, its rows from ``CREATE_USER`` and its provider
identity are committed.

Arguments: ``user``, the native user. A failing receiver cannot undo the sign-up.
"""

before_social_account_create = Signal()
"""Sent before a provider identity is connected to a user: at sign-up, when a
sign-in connects it, or when a link connects it.

Arguments: ``user_id``, ``provider_user_id``, ``email``, ``email_verified``
and ``is_login_method``. At sign-up it runs inside the sign-up's transaction,
so refusing creates no user either.
"""

social_account_created = Signal()
"""Sent once a new provider identity is committed.

Arguments: ``social_account``, the ``cross_auth.SocialAccount``.
"""

before_social_account_update = Signal()
"""Sent before a connected identity is refreshed with the provider's latest
email: on every later sign-in, and when a link reconnects it.

Arguments: ``social_account_id``, ``user_id``, ``provider_user_id``, the new
``email`` and ``email_verified``, and the stored ``is_login_method``.
"""

social_account_updated = Signal()
"""Sent once the refreshed identity is committed.

Arguments: ``social_account``, the updated ``cross_auth.SocialAccount``.
"""

social_account_linked = Signal()
"""Sent after a link callback committed its identity, following
``social_account_created`` or ``social_account_updated``.

Arguments: ``social_account``. Sign-ins and sign-ups never send it.
"""

before_login = Signal()
"""Sent before a provider sign-in logs a user in.

Arguments: ``user_id`` (the primary key as a string) and ``email``. On a first
sign-in the user already exists; refuse in ``before_user_create`` to stop
sign-ups.
"""

after_login = Signal()
"""Sent once the provider sign-in's session is saved.

Arguments: ``user``, the native user. Django's ``user_logged_in`` was sent
before it. A failing receiver cannot undo the login.
"""

before_social_account_disconnect = Signal()
"""Sent before the disconnect view removes one of the signed-in user's
identities.

Arguments: ``social_account_id``, ``user_id`` and ``provider_user_id``.
"""

social_account_disconnected = Signal()
"""Sent once the identity's removal is committed. Not sent when it was the
user's last way to sign in and stayed.

Arguments: ``social_account``, the removed ``cross_auth.SocialAccount``; its
``pk`` and ``user_id`` still name what it was.
"""

before_session_revoke = Signal()
"""Sent by ``revoke_session`` and ``revoke_other_sessions`` in
``cross_auth.django.sessions`` before they sign out any session.

Arguments: ``user_id``, ``scope`` (``"one"`` for ``revoke_session``,
``"others"`` for ``revoke_other_sessions``) and ``session_id``, the session's
``id`` for ``"one"`` and ``None`` for ``"others"``. ``revoke_session`` sends it
only for an active session of the signed-in user. No ``provider``. Refusing
signs nothing out.
"""

session_revoked = Signal()
"""Sent once sessions were signed out; not sent when none were.

Arguments: ``user`` (``request.user``, as Django's ``user_logged_out`` sends
it), ``scope``, ``session_id`` and ``revoked_count``, how many sessions were
signed out. No ``provider``.
"""
