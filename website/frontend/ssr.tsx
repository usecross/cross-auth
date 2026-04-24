import { DocsPage } from '@usecross/docs'
import { createDocsServer } from '@usecross/docs/ssr'

import Home from './pages/Home'

createDocsServer({
  pages: {
    Home,
    'docs/DocsPage': DocsPage,
  },
  title: (title) => (title ? `${title} - Cross-Auth` : 'Cross-Auth'),
})
