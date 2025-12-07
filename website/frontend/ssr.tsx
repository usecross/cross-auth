import './globals.css'
import { createInertiaApp } from '@inertiajs/react'
import { renderToString } from 'react-dom/server'

export async function render(page: unknown) {
  return createInertiaApp({
    page,
    render: renderToString,
    resolve: (name) => {
      const pages = import.meta.glob('./pages/**/*.tsx', { eager: true })
      return pages[`./pages/${name}.tsx`]
    },
    setup: ({ App, props }) => <App {...props} />,
    title: (title) => (title ? `${title} - Cross-Auth` : 'Cross-Auth'),
  })
}
