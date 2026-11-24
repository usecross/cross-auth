# Example frontend

The React pages for both example backends, rendered with
[Inertia](https://inertiajs.com) through
[cross-inertia](https://github.com/usecross/cross-inertia). `src/pages/fastapi`
holds the FastAPI example's pages and `src/pages/django` the Django example's;
both use the components in `src/components` and the stylesheet in
`src/styles.css`, so the examples look the same.

```bash
bun install
bun run build   # writes dist/, which both backends serve at /static/build/
bun run dev     # or: a Vite dev server on port 5174, with hot reload
```

Each backend uses the dev server when it answers on port 5174 and the build
otherwise. Django's `runserver` starts the dev server itself while `DEBUG` is on
(set `INERTIA_DEV=0` to stop it); for FastAPI, run `bun run dev` here yourself.
