import { join, resolve } from "node:path"

import { expect } from "@playwright/test"

import type { AccountFacts, App, Framework } from "../support/app.js"
import {
  emulatorUrl,
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
} from "../support/google.js"
import { run, startServer } from "../support/process.js"

const exampleDir = resolve(import.meta.dirname, "../../../examples/fastapi")
const python = [
  "uv",
  "run",
  "--frozen",
  "--package",
  "cross-auth-fastapi-example",
  "python",
]

export const fastapi: Framework = {
  basePort: 8180,

  async start({ port, dataDir, logFile }) {
    const baseURL = `http://127.0.0.1:${port}`
    const database = join(dataDir, "db.sqlite3")
    const command = (...args: string[]) => ({
      args: [...python, ...args],
      cwd: exampleDir,
      env: {
        PYTHONUNBUFFERED: "1",
        EXAMPLE_BASE_URL: baseURL,
        EXAMPLE_DATABASE_URL: `sqlite:///${database}`,
        E2E_DATABASE: database,
        GOOGLE_EMULATOR_URL: emulatorUrl(),
        GOOGLE_CLIENT_ID,
        GOOGLE_CLIENT_SECRET,
      },
    })
    const state = (...args: string[]) =>
      run(command(join(import.meta.dirname, "state.py"), ...args))

    // The app creates its tables and demo users at startup.
    const server = await startServer(
      command(
        "-m",
        "uvicorn",
        "main:app",
        "--host",
        "127.0.0.1",
        "--port",
        String(port),
      ),
      { readyUrl: `${baseURL}/`, logFile },
    )

    const app: App & { stop(): Promise<void> } = {
      baseURL,
      googleCallbackUrl: `${baseURL}/auth/google/callback`,
      stop: server.stop,

      async startGoogleSignIn(page) {
        await page.goto(`${baseURL}/`)
        await page.getByRole("link", { name: "Continue with Google" }).click()
      },

      async signInWithPassword(page, email, password) {
        await page.goto(`${baseURL}/`)
        await page.getByLabel("Email").fill(email)
        await page.getByLabel("Password").fill(password)
        await page
          .getByRole("button", { name: "Sign in with password" })
          .click()
      },

      async startGoogleConnect(page) {
        // The PKCE link flow with allow_login connects Google as a way to
        // sign in, like Django's link view. "Connect Google (session)" only
        // adds an integration; fastapi/connect-integration.spec.ts covers it.
        await page.getByRole("button", { name: "Link Google account" }).click()
      },

      async disconnectGoogle(page, providerEmail) {
        // The profile page disconnects with a DELETE request and reloads.
        await app
          .googleAccount(page, providerEmail)
          .getByRole("button", { name: "Disconnect" })
          .click()
      },

      async signOut(page) {
        await page.getByRole("button", { name: "Log out" }).click()
        await expect(
          page.getByRole("button", { name: "Sign in with password" }),
        ).toBeVisible()
      },

      async gotoProfile(page) {
        await page.goto(`${baseURL}/profile`)
      },

      profileHeading(page, email) {
        return page.getByRole("heading", { level: 1, name: email, exact: true })
      },

      googleAccount(page, providerEmail) {
        return page
          .locator("li[data-social-account-id]")
          .filter({ hasText: "google" })
          .filter({ hasText: providerEmail })
      },

      async expectSignedOut(page) {
        await page.goto(`${baseURL}/profile`)
        await expect(page).toHaveURL(`${baseURL}/`)
        await expect(
          page.getByRole("button", { name: "Sign in with password" }),
        ).toBeVisible()
      },

      async seedPasswordUser(email, password) {
        await state("seed-password-user", email, password)
      },

      async facts(email) {
        return JSON.parse(await state("facts", email)) as AccountFacts
      },
    }
    return app
  },
}
