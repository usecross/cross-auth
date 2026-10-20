import { defineConfig } from "@playwright/test"

import { type FrameworkName, frameworks } from "./frameworks/frameworks.js"
import { MAX_WORKERS } from "./frameworks/support/google.js"

// The shared browser contract, run once per framework example app against a
// local Google emulator. See README.md; the legacy FastAPI + SPA suite keeps
// its own playwright.config.js.
export default defineConfig<object, { framework: FrameworkName }>({
  testDir: "./frameworks",
  globalSetup: "./frameworks/support/global-setup.ts",
  outputDir: "./test-results/frameworks",
  workers: process.env.CI ? 2 : Math.min(4, MAX_WORKERS),
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI
    ? [
        ["list"],
        [
          "html",
          { open: "never", outputFolder: "playwright-report/frameworks" },
        ],
      ]
    : "list",
  use: { trace: "retain-on-failure" },
  projects: (Object.keys(frameworks) as FrameworkName[]).map((name) => ({
    name,
    testMatch: ["contract/**/*.spec.ts", `${name}/**/*.spec.ts`],
    use: { framework: name },
  })),
})
