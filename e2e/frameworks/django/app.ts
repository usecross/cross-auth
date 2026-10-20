import { join, resolve } from "node:path"

import { expect } from "@playwright/test"

import type { AccountFacts, App, Framework } from "../support/app.js"
import {
  emulatorUrl,
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
} from "../support/google.js"
import { run, startServer } from "../support/process.js"

const exampleDir = resolve(import.meta.dirname, "../../../examples/django")
const python = [
  "uv",
  "run",
  "--frozen",
  "--package",
  "cross-auth-django-example",
  "python",
]

export const django: Framework = {
  basePort: 8280,

  async start({ port, dataDir, logFile }) {
    const baseURL = `http://127.0.0.1:${port}`
    const command = (...args: string[]) => ({
      args: [...python, ...args],
      cwd: exampleDir,
      env: {
        DJANGO_SETTINGS_MODULE: "e2e_settings",
        PYTHONPATH: `${import.meta.dirname}:${exampleDir}`,
        PYTHONUNBUFFERED: "1",
        E2E_DATABASE: join(dataDir, "db.sqlite3"),
        GOOGLE_EMULATOR_URL: emulatorUrl(),
        GOOGLE_CLIENT_ID,
        GOOGLE_CLIENT_SECRET,
        // core/signals.py refuses Google accounts outside this domain.
        ALLOWED_EMAIL_DOMAIN: "e2e.test",
      },
    })
    const state = (...args: string[]) =>
      run(command(join(import.meta.dirname, "state.py"), ...args))

    await run(command("manage.py", "migrate", "--noinput"))
    const server = await startServer(
      command("manage.py", "runserver", `127.0.0.1:${port}`, "--noreload"),
      {
        readyUrl: `${baseURL}/`,
        logFile,
      },
    )

    const app: App & { stop(): Promise<void> } = {
      baseURL,
      googleCallbackUrl: `${baseURL}/auth/google/callback`,
      stop: server.stop,

      async startGoogleSignIn(page) {
        await page.goto(`${baseURL}/`)
        await page.getByRole("button", { name: "Sign in with Google" }).click()
      },

      async signInWithPassword(page, email, password) {
        await page.goto(`${baseURL}/accounts/login/?next=/profile/`)
        await page.getByLabel("Username").fill(email)
        await page.getByLabel("Password").fill(password)
        await page.getByRole("button", { name: "Sign in", exact: true }).click()
      },

      async startGoogleConnect(page) {
        await page.getByRole("button", { name: "Connect Google" }).click()
      },

      async disconnectGoogle(page, providerEmail) {
        await app
          .googleAccount(page, providerEmail)
          .getByRole("button", { name: "Disconnect" })
          .click()
      },

      async signOut(page) {
        await page.getByRole("button", { name: "Sign out" }).click()
        await expect(
          page.getByRole("button", { name: "Sign in with Google" }),
        ).toBeVisible()
      },

      async gotoProfile(page) {
        await page.goto(`${baseURL}/profile/`)
      },

      profileHeading(page, email) {
        return page.getByRole("heading", { level: 1, name: email, exact: true })
      },

      googleAccount(page, providerEmail) {
        return page
          .getByRole("listitem")
          .filter({ hasText: `google: ${providerEmail}` })
      },

      async expectSignedOut(page) {
        await page.goto(`${baseURL}/profile/`)
        await expect(page).toHaveURL(
          `${baseURL}/accounts/login/?next=/profile/`,
        )
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
