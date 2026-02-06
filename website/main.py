import os

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from cross_inertia import configure_inertia
from cross_inertia.fastapi import InertiaMiddleware
from cross_inertia.fastapi.experimental import inertia_lifespan

from cross_docs import CrossDocs

# Configure Inertia (vite root is 'frontend', so entry is just 'app.tsx')
configure_inertia(vite_entry="app.tsx")

# Only use inertia_lifespan in dev mode (auto-starts Vite)
# In production, we don't need it since we serve pre-built static files
lifespan = inertia_lifespan if os.getenv("INERTIA_DEV") else None

app = FastAPI(title="Cross-Auth Docs", docs_url=None, redoc_url=None, lifespan=lifespan)

# Serve static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Add Inertia middleware
app.add_middleware(InertiaMiddleware)

# Mount docs (includes homepage from config)
docs = CrossDocs()
docs.mount(app)
