import { createInertiaApp } from "@inertiajs/react"
import type { ComponentType } from "react"
import { createRoot } from "react-dom/client"

import "./styles.css"

// Component names are "fastapi/Home", "django/Profile" and so on: each
// backend renders its own pages, built from the shared components.
const pages = import.meta.glob<{ default: ComponentType }>("./pages/**/*.tsx", {
  eager: true,
})

createInertiaApp({
  resolve: (name) => {
    const page = pages[`./pages/${name}.tsx`]
    if (!page) throw new Error(`Unknown page: ${name}`)
    return page.default
  },
  setup({ el, App, props }) {
    createRoot(el).render(<App {...props} />)
  },
})
