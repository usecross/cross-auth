"""Signals sent around Cross Auth's provider sign-ins.

Connect receivers with ``@receiver`` in a module that your app's
``AppConfig.ready()`` imports. Each signal's sender is the user model, and
every receiver gets ``request`` (the ``HttpRequest`` of the provider callback)
and ``provider`` (the provider ID, such as ``"google"``) besides the arguments
listed below.

Signals are sent with ``Signal.send()``: a receiver's exception propagates and
return values are ignored. Raise ``PermissionDenied`` from a ``before_*``
receiver to refuse; Django answers with its 403 response.

They cover only Cross Auth's provider flows. Django's own ``user_logged_in``,
``user_logged_out`` and ``user_login_failed`` cover every login, including
password logins, and are sent by Django as usual.
"""

from django.dispatch import Signal

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
