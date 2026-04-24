import inertia from '@inertiajs/vite'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import path from 'path'
import { defineConfig } from 'vite'

export default defineConfig(({ command, isSsrBuild }) => ({
  plugins: [tailwindcss(), react(), inertia()],
  base: command === 'serve' || isSsrBuild ? '/' : '/static/build/',
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './frontend'),
    },
    dedupe: ['@inertiajs/react', 'react', 'react-dom'],
  },
  build: {
    manifest: !isSsrBuild,
    outDir: isSsrBuild ? 'static/build/ssr' : 'static/build',
    emptyOutDir: !isSsrBuild,
    rollupOptions: {
      input: isSsrBuild ? 'frontend/ssr.tsx' : 'frontend/app.tsx',
      output: isSsrBuild
        ? {
            entryFileNames: 'ssr.js',
          }
        : undefined,
    },
  },
  ssr: {
    noExternal: isSsrBuild ? true : ['shiki', '@inertiajs/react'],
  },
  server: {
    origin: 'http://localhost:5173',
  },
}))
