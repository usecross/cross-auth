import os

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from cross_inertia import configure_inertia
from cross_inertia.fastapi.experimental import inertia_lifespan

from cross_docs import CrossDocs

configure_inertia(vite_entry="frontend/app.tsx")

# Production serves pre-built assets without starting Vite.
lifespan = inertia_lifespan if os.getenv("INERTIA_DEV") else None

app = FastAPI(title="Cross-Auth Docs", docs_url=None, redoc_url=None, lifespan=lifespan)

app.mount("/static", StaticFiles(directory="static"), name="static")

docs = CrossDocs()
docs.mount(app)
