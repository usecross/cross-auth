import { mkdirSync, mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { test as base, expect } from "@playwright/test"

import { type FrameworkName, frameworks } from "../frameworks.js"
import type { App } from "./app.js"
import {
  type GoogleIdentity,
  googleIdentity,
  type IdentityName,
  MAX_WORKERS,
} from "./google.js"

interface WorkerFixtures {
  framework: FrameworkName
  server: App & { logFile: string }
}

interface TestFixtures {
  app: App
  // A Google account reserved for one scenario.
  googleUser(name: IdentityName): GoogleIdentity
}

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost"])

export const test = base.extend<TestFixtures, WorkerFixtures>({
  framework: ["django", { option: true, scope: "worker" }],

  // One app server per worker with its own database, started fresh for
  // every run, so workers and reruns never share state.
  server: [
    async ({ framework }, use, workerInfo) => {
      if (workerInfo.parallelIndex >= MAX_WORKERS) {
        throw new Error(
          `The Google emulator allows at most ${MAX_WORKERS} workers`,
        )
      }
      const dataDir = mkdtempSync(
        join(tmpdir(), `cross-auth-e2e-${framework}-`),
      )
      const logDir = join(workerInfo.project.outputDir, "servers")
      mkdirSync(logDir, { recursive: true })
      const logFile = join(
        logDir,
        `${framework}-${workerInfo.parallelIndex}.log`,
      )
      const { stop, ...app } = await frameworks[framework].start({
        port: frameworks[framework].basePort + workerInfo.parallelIndex,
        dataDir,
        logFile,
      })
      try {
        await use({ ...app, logFile })
      } finally {
        await stop()
        rmSync(dataDir, { recursive: true, force: true })
      }
    },
    { scope: "worker", timeout: 120_000 },
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
