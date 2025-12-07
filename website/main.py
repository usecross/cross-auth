from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from inertia.fastapi import InertiaMiddleware, InertiaDep

app = FastAPI(title="Cross-Auth Docs", docs_url=None, redoc_url=None)

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
            "githubUrl": "https://github.com/patrick91/cross-auth",
            "navLinks": [{"label": "Docs", "href": "/docs"}],
        },
    )
