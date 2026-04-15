import { defineConfig } from "@playwright/test"
import path from "node:path"
import { fileURLToPath } from "node:url"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

export default defineConfig({
  testDir: "./tests",
  timeout: 60_000,
  workers: 1,
  use: {
    headless: true,
  },
  webServer: [
    {
      command:
        "uv run --package cross-auth-fastapi-example fastapi dev examples/fastapi/main.py --host 127.0.0.1 --port 8000",
      url: "http://127.0.0.1:8000",
      cwd: path.resolve(__dirname, "../.."),
      timeout: 120_000,
      reuseExistingServer: !process.env.CI,
    },
    {
      command: "bun run dev -- --host 127.0.0.1 --port 5173",
      url: "http://127.0.0.1:5173",
      cwd: __dirname,
      timeout: 120_000,
      reuseExistingServer: !process.env.CI,
    },
  ],
})
