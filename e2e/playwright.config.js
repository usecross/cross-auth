import { defineConfig } from "@playwright/test"

const reuseExistingServer = Boolean(process.env.PLAYWRIGHT_REUSE_SERVERS)

export default defineConfig({
  testDir: "./tests",
  webServer: [
    {
      command:
        "uv run --package cross-auth-fastapi-example uvicorn main:app --host 127.0.0.1 --port 8000",
      cwd: "../examples/fastapi",
      url: "http://127.0.0.1:8000/",
      reuseExistingServer,
      stdout: "pipe",
      stderr: "pipe",
      timeout: 120_000,
    },
    {
      command: "bun run dev -- --host 127.0.0.1 --port 5173",
      cwd: "../examples/spa",
      url: "http://127.0.0.1:5173/",
      reuseExistingServer,
      stdout: "pipe",
      stderr: "pipe",
      timeout: 120_000,
    },
  ],
  use: {
    trace: "retain-on-failure",
  },
})
