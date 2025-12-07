import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig(({ command }) => ({
  plugins: [react()],
  base: command === 'build' ? '/static/build/' : '/',
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './frontend'),
    },
    dedupe: ['@inertiajs/react', 'react', 'react-dom'],
  },
  build: {
    manifest: true,
    outDir: 'static/build',
    rollupOptions: {
      input: 'frontend/app.tsx',
    },
  },
}))
