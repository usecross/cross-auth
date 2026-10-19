import nox

nox.options.default_venv_backend = "uv"

PYTHON_VERSIONS = ["3.11", "3.12", "3.13", "3.14"]


@nox.session(python=PYTHON_VERSIONS, tags=["tests"])
def tests(session: nox.Session) -> None:
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
    session.run("coverage", "run", "-m", "pytest", *session.posargs)


@nox.session(python=["3.14"], tags=["typecheck"])
def typecheck(session: nox.Session) -> None:
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
    session.run("ty", "check", ".", "--exclude", "website")


# The main tests session covers SQLite with Django's user model. This one adds
# PostgreSQL (in a disposable container) and a custom UUID user model.
@nox.session(python=["3.14"], tags=["tests"])
@nox.parametrize("database", ["sqlite", "postgres"])
@nox.parametrize("user_model", ["default", "custom"])
def django(session: nox.Session, database: str, user_model: str) -> None:
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
