import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

// One frontend for both example backends. Each serves the build output at
// /static/build/ and reads dist/.vite/manifest.json through cross-inertia;
// in development both point at the same Vite dev server under that base.
export default defineConfig({
  plugins: [react()],
  base: "/static/build/",
  build: {
    manifest: true,
    outDir: "dist",
    emptyOutDir: true,
    rollupOptions: { input: "src/app.tsx" },
  },
  // The backends look for the dev server here (vite_port / VITE_PORT).
  server: { port: 5174, strictPort: true },
})
