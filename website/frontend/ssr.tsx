import './globals.css'
import { createInertiaApp } from '@inertiajs/react'
import { renderToString } from 'react-dom/server'
import { DocsPage, ThemeProvider } from '@usecross/docs'

// Import page components
import Home from './pages/Home'

const pages: Record<string, React.ComponentType<any>> = {
  Home,
  'docs/DocsPage': DocsPage,
}

export async function render(page: unknown) {
  return createInertiaApp({
    page,
    render: renderToString,
    resolve: (name) => {
      const pageComponent = pages[name]
      if (!pageComponent) {
        throw new Error(`Page component "${name}" not found`)
      }
      return pageComponent
    },
    setup: ({ App, props }) => (
      <ThemeProvider>
        <App {...props} />
      </ThemeProvider>
    ),
    title: (title) => (title ? `${title} - Cross-Auth` : 'Cross-Auth'),
  })
}
