import { join, resolve } from "node:path"

import type { AccountFacts, App, Framework } from "../support/app.js"
import { createBrowserApp } from "../support/browser.js"
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
      run(command("manage.py", "e2e_state", ...args))

    await run(command("manage.py", "migrate", "--noinput"))
    const server = await startServer(
      command("manage.py", "runserver", `127.0.0.1:${port}`, "--noreload"),
      {
        readyUrl: `${baseURL}/`,
        logFile,
      },
    )

    const app: App & { stop(): Promise<void> } = {
      ...createBrowserApp(baseURL, {
        routes: {
          signIn: "/accounts/login/?next=/profile/",
          profile: "/profile/",
        },
        googleSignIn: { role: "button", name: "Sign in with Google" },
        password: { identifierLabel: "Username", submitName: "Sign in" },
        googleConnect: "Connect Google",
        signOut: "Sign out",
        googleAccount: { selector: "li", providerText: "google:" },
      }),
      stop: server.stop,

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
