import os

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from cross_inertia.fastapi import InertiaMiddleware, InertiaDep
from cross_inertia.fastapi.experimental import inertia_lifespan

# Only use inertia_lifespan in dev mode (auto-starts Vite)
# In production, we don't need it since we serve pre-built static files
lifespan = inertia_lifespan if os.getenv("INERTIA_DEV") else None

app = FastAPI(title="Cross-Auth Docs", docs_url=None, redoc_url=None, lifespan=lifespan)

app.mount("/static", StaticFiles(directory="static"), name="static")

app.add_middleware(InertiaMiddleware)


@app.get("/")
async def home(inertia: InertiaDep):
    return inertia.render(
        "Home",
        {
            "title": "Cross-Auth",
            "tagline": "Python Authentication",
            "description": "Simple, secure authentication for Python web applications. Works with Django, Flask, and FastAPI.",
            "installCommand": "uv add cross-auth",
            "ctaText": "Get Started",
            "ctaHref": "/docs",
            "features": [
                {
                    "title": "Framework Agnostic",
                    "description": "Works seamlessly with Django, Flask, FastAPI, and other Python web frameworks.",
                },
                {
                    "title": "Secure by Default",
                    "description": "Built-in protection against common vulnerabilities. Secure session handling out of the box.",
                },
                {
                    "title": "Easy to Use",
                    "description": "Simple API that gets you up and running in minutes. No complex configuration required.",
                },
                {
                    "title": "Extensible",
                    "description": "Customizable authentication flows. Add your own providers and strategies.",
                },
            ],
            "logoUrl": "/static/logo.svg",
            "heroLogoUrl": "/static/logo-full.svg",
            "footerLogoUrl": "/static/logo-full.svg",
            "githubUrl": "https://github.com/patrick91/cross-auth",
            "navLinks": [{"label": "Docs", "href": "/docs"}],
        },
    )
