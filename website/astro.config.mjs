// @ts-check
import { defineConfig } from 'astro/config';

import tailwindcss from '@tailwindcss/vite';
import mdx from '@astrojs/mdx';

// https://astro.build/config
export default defineConfig({
  integrations: [mdx()],
  vite: {
    plugins: [tailwindcss()],
  },
  markdown: {
    shikiConfig: {
      // Choose from Shiki's built-in themes (or provide your own)
      // https://shiki.style/themes
      theme: 'catppuccin-latte',
      // Or use multiple themes
      // themes: {
      //   light: 'github-light',
      //   dark: 'github-dark',
      // },
      // Add custom languages
      // https://shiki.style/languages
      langs: [],
      // Enable word wrap to prevent horizontal scrolling
      wrap: true,
    },
  },
});
