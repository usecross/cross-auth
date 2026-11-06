import { mkdirSync, mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"

import { test as base, expect } from "@playwright/test"
import { createEmulator } from "emulate"

import { fastapi } from "../../frameworks/fastapi/app.js"
import { startServer } from "../../frameworks/support/process.js"

interface Scenario {
  backend: string
  spa: string
  socialIdentity: { email: string; id: string }
}

// Each scenario, including retries and repeats, owns all mutable server state.
// Worker-indexed ports are reused only after the previous scenario has stopped.
export const test = base.extend<Scenario & { scenario: Scenario }>({
  scenario: [async ({}, use, testInfo) => {
    const backendPort = 8380 + testInfo.parallelIndex
    const spaPort = 9380 + testInfo.parallelIndex
    const backend = `http://127.0.0.1:${backendPort}`
    const spa = `http://127.0.0.1:${spaPort}`
    const dataDir = mkdtempSync(join(tmpdir(), "cross-auth-scenario-"))
    const logDir = join(testInfo.outputDir, "servers")
    mkdirSync(logDir, { recursive: true })
    const email = "scenario@e2e.test"
    const github = await createEmulator({
      service: "github", port: 0, hostname: "127.0.0.1",
      seed: { github: {
        users: [{ login: "scenario", name: "Scenario", email }],
        oauth_apps: [{
          client_id: "demo-client", client_secret: "demo-secret",
          name: "Cross Auth", redirect_uris: [`${backend}/auth/github/callback`],
        }],
      } },
    })
    let stopBackend: (() => Promise<void>) | undefined
    let stopSpa: (() => Promise<void>) | undefined
    try {
      const identity = await (await fetch(`${github.url}/users/scenario`)).json() as { id: number }
      const app = await fastapi.start({
        port: backendPort, dataDir, logFile: join(logDir, "backend.log"),
        env: { GITHUB_EMULATOR_URL: github.url, EXAMPLE_SPA_ORIGINS: spa },
      })
      stopBackend = app.stop
      const frontend = await startServer({
        args: ["bun", "run", "dev", "--", "--host", "127.0.0.1", "--port", String(spaPort), "--strictPort"],
        cwd: resolve(import.meta.dirname, "../../../examples/spa"),
        env: { VITE_BACKEND_BASE_URL: backend },
      }, { readyUrl: spa, logFile: join(logDir, "spa.log") })
      stopSpa = frontend.stop
      await use({ backend, spa, socialIdentity: { email, id: String(identity.id) } })
    } finally {
      try {
        await stopSpa?.()
      } finally {
        try { await stopBackend?.() } finally {
          await github.close()
          rmSync(dataDir, { recursive: true, force: true })
        }
      }
    }
  }, { timeout: 120_000 }],
  backend: async ({ scenario }, use) => use(scenario.backend),
  spa: async ({ scenario }, use) => use(scenario.spa),
  socialIdentity: async ({ scenario }, use) => use(scenario.socialIdentity),
  context: async ({ context }, use) => {
    const external: string[] = []
    await context.route(url => !["127.0.0.1", "localhost"].includes(url.hostname), route => {
      external.push(route.request().url())
      return route.abort("blockedbyclient")
    })
    await use(context)
    expect(external, "browser requests outside loopback").toEqual([])
  },
})

export { expect }
