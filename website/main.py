"""Cross Auth Documentation Site."""

import os
import signal
import subprocess
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from inertia.fastapi import InertiaMiddleware
import inertia._core

from cross_docs import create_docs_router_from_config, strip_trailing_slash_middleware

# Auto-detect dev mode (for `fastapi dev`)
DEBUG = "dev" in sys.argv

# Configure Inertia response (set singleton before it's accessed)
inertia_response = inertia._core.InertiaResponse(
    template_dir="templates",
    manifest_path="frontend/dist/.vite/manifest.json",
    vite_entry="frontend/app.tsx",
    vite_dev_url="http://localhost:5173" if DEBUG else None,
)
inertia._core._inertia_response = inertia_response


def _kill_process_group(process: subprocess.Popen, name: str) -> None:
    """Kill a process and all its children using process group."""
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        process.wait(timeout=5)
        print(f"Stopped {name}")
    except ProcessLookupError:
        pass
    except subprocess.TimeoutExpired:
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        process.wait()
        print(f"Force killed {name}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage Vite dev server lifecycle."""
    vite_process = None

    if DEBUG:
        # Start Vite dev server in its own process group
        vite_process = subprocess.Popen(
            ["bun", "run", "dev"],
            start_new_session=True,
        )
        print("Started Vite dev server on http://localhost:5173")

    yield

    if vite_process:
        _kill_process_group(vite_process, "Vite dev server")


def share_data(request) -> dict:
    """Shared data available on all pages."""
    return {}


app = FastAPI(title="Cross Auth Docs", lifespan=lifespan, docs_url=None, redoc_url=None)

# Strip trailing slashes
app.middleware("http")(strip_trailing_slash_middleware)

# Serve static files
static_path = Path(__file__).parent / "frontend" / "dist"
if static_path.exists():
    app.mount("/static/build", StaticFiles(directory=static_path), name="static_build")

# Serve favicon and other static assets
public_path = Path(__file__).parent / "static"
if public_path.exists():
    app.mount("/static", StaticFiles(directory=public_path), name="static")

# Add Inertia middleware
app.add_middleware(InertiaMiddleware, share=share_data)

# Create and include docs router (reads config from pyproject.toml)
docs_router = create_docs_router_from_config()
app.include_router(docs_router)


# Redirect root to docs
@app.get("/")
async def root():
    from fastapi.responses import RedirectResponse

    return RedirectResponse(url="/docs")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
