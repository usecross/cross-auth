import nox

nox.options.default_venv_backend = "uv"

PYTHON_VERSIONS = ["3.11", "3.12", "3.13", "3.14", "3.15"]


def _sync_dev(session: nox.Session) -> None:
    session.run_install(
        "uv",
        "sync",
        "--frozen",
        "--package",
        "cross-auth",
        "--group",
        "dev",
        env={"UV_PROJECT_ENVIRONMENT": session.virtualenv.location},
    )


@nox.session(python=PYTHON_VERSIONS, tags=["tests"])
def tests(session: nox.Session) -> None:
    _sync_dev(session)
    session.run("coverage", "run", "-m", "pytest", *session.posargs)


@nox.session(python=["3.14"], tags=["typecheck"])
def typecheck(session: nox.Session) -> None:
    _sync_dev(session)
    session.run("ty", "check", ".", "--exclude", "website")


# Exercise each supported Django series with both databases and user models.
# Python 3.15 is only supported by Django 6.1.3 and later.
@nox.session(tags=["tests"])
@nox.parametrize(
    "python,django_version",
    [("3.14", "5.2"), ("3.14", "6.0"), ("3.14", "6.1"), ("3.15", "6.1")],
)
@nox.parametrize("database", ["sqlite", "postgres"])
@nox.parametrize("user_model", ["default", "custom"])
def django(
    session: nox.Session, django_version: str, database: str, user_model: str
) -> None:
    _sync_dev(session)
    session.install(f"django=={django_version}.*")
    session.run("python", "-m", "django", "--version")
    session.run(
        "coverage",
        "run",
        "-m",
        "pytest",
        "tests/django",
        *session.posargs,
        env={
            "CROSS_AUTH_TEST_DATABASE": database,
            "CROSS_AUTH_TEST_USER_MODEL": user_model,
        },
    )


# Django's development branch, so a change to the session store internals that
# cross_auth.django.sessions overrides shows up before a release ships it. Not
# tagged "tests": .github/workflows/django-main.yml runs it on pull requests,
# without blocking them, and weekly.
@nox.session(python=["3.14"], tags=["django-main"])
@nox.parametrize("database", ["sqlite", "postgres"])
def django_main(session: nox.Session, database: str) -> None:
    _sync_dev(session)
    session.install("git+https://github.com/django/django@main")
    session.run("python", "-m", "django", "--version")
    session.run(
        "pytest",
        "tests/django",
        *session.posargs,
        env={
            "CROSS_AUTH_TEST_DATABASE": database,
            "CROSS_AUTH_TEST_USER_MODEL": "default",
        },
    )
