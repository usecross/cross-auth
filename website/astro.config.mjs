// @ts-check
import { defineConfig } from 'astro/config';
import mdx from '@astrojs/mdx';
import docsTheme from '@usecross/astro-docs-theme';

// https://astro.build/config
export default defineConfig({
  integrations: [
    mdx(),
    docsTheme({
      title: 'Cross Auth',
      description: 'Universal Python Authentication - One library to handle JWTs, OAuth2, and Session Auth across FastAPI, Django, and Flask.',
      logo: {
        src: '/logo.svg',
        alt: 'Cross Auth',
      },
      footerLogo: {
        src: '/logo-full.svg',
        alt: 'Cross Auth',
      },
      social: {
        github: 'https://github.com/patrick91/cross-auth',
      },
      colors: {
        primary: '#6466F1',
      },
      hero: {
        heading: '<span class="text-primary">Cross Auth</span>',
        description: 'Universal Python Authentication - One library to handle JWTs, OAuth2, and Session Auth across FastAPI, Django, and Flask.',
        primaryCta: { label: 'Get Started', href: '/docs' },
        installCommand: 'pip install cross-auth',
      },
      footerLinks: [
        { label: 'Documentation', href: '/docs' },
        { label: 'PyPI', href: 'https://pypi.org/project/cross-auth/', external: true },
      ],
    }),
  ],
});
