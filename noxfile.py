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
