import { mkdirSync, mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { test as base, expect } from "@playwright/test"
import { createEmulator } from "emulate"

import { type FrameworkName, frameworks } from "../frameworks.js"
import type { App } from "./app.js"
import { frameworkPort } from "./plan.js"
import {
  type GoogleIdentity,
  googleIdentity,
  googleSeed,
  type IdentityName,
} from "./google.js"

interface WorkerFixtures {
  framework: FrameworkName
}

interface TestFixtures {
  server: App & { logFile: string }
  app: App
  // A Google account reserved for one scenario.
  googleUser(name: IdentityName): GoogleIdentity
}

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost"])

export const test = base.extend<TestFixtures, WorkerFixtures>({
  framework: ["django", { option: true, scope: "worker" }],

  // A fresh app, database and provider for every scenario, retry and repeat.
  server: [
    async ({ framework }, use, testInfo) => {
      const logDir = join(testInfo.outputDir, "servers")
      mkdirSync(logDir, { recursive: true })
      const logFile = join(
        logDir,
        `${framework}-${testInfo.parallelIndex}.log`,
      )
      const dataDir = mkdtempSync(
        join(tmpdir(), `cross-auth-e2e-${framework}-`),
      )
      const port = frameworkPort(testInfo.config, testInfo.project, testInfo.parallelIndex)
      // TestInfo carries the actual CLI-resolved repeat index. Playwright's
      // global setup and worker project config do not expose that override.
      const emulator = await createEmulator({
        service: "google", port: 0, hostname: "127.0.0.1",
        seed: googleSeed(
          [`http://127.0.0.1:${port}/auth/google/callback`],
          [testInfo.repeatEachIndex],
        ),
      })
      process.env.GOOGLE_EMULATOR_URL = emulator.url
      let stop: (() => Promise<void>) | undefined
      try {
        const { stop: stopServer, ...app } = await frameworks[framework].start({
          port,
          dataDir,
          logFile,
        })
        stop = stopServer
        await use({ ...app, logFile })
      } finally {
        try {
          await stop?.()
        } finally {
          await emulator.close()
          delete process.env.GOOGLE_EMULATOR_URL
          rmSync(dataDir, { recursive: true, force: true })
        }
      }
    },
    { timeout: 120_000 },
  ],

  app: async ({ server }, use, testInfo) => {
    await use(server)
    if (testInfo.status !== testInfo.expectedStatus) {
      await testInfo.attach("server.log", {
        path: server.logFile,
        contentType: "text/plain",
      })
    }
  },

  baseURL: async ({ server }, use) => {
    await use(server.baseURL)
  },

  // Fails a test whose browser tried to leave the machine: every provider
  // page must come from the local emulator.
  context: async ({ context }, use) => {
    const external: string[] = []
    await context.route(
      (url) => !LOOPBACK_HOSTS.has(url.hostname),
      (route) => {
        external.push(route.request().url())
        return route.abort("blockedbyclient")
      },
    )
    await use(context)
    expect(external, "browser requests outside loopback").toEqual([])
  },

  googleUser: async ({}, use, testInfo) => {
    await use((name) => googleIdentity(name, testInfo.repeatEachIndex))
  },
})

export { expect }
