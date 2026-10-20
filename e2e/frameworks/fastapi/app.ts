import { join, resolve } from "node:path"

import type { AccountFacts, App, Framework } from "../support/app.js"
import { createBrowserApp } from "../support/browser.js"
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
      ...createBrowserApp(baseURL, {
        routes: { signIn: "/", profile: "/profile" },
        googleSignIn: { role: "link", name: "Continue with Google" },
        password: {
          identifierLabel: "Email",
          submitName: "Sign in with password",
        },
        // Login-enabled PKCE linking, not the integration-only /connect.
        googleConnect: "Link Google account",
        signOut: "Log out",
        googleAccount: {
          selector: "li[data-social-account-id]",
          providerText: "google",
        },
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
