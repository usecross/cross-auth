import { expect } from "@playwright/test"

import type { App } from "./app.js"

// Only the example apps' routes and UI labels differ. Browser actions and
// profile/session checks are implemented once below, not in each framework.
interface BrowserUI {
  routes: { signIn: string; profile: string }
  googleSignIn: { role: "button" | "link"; name: string }
  password: { identifierLabel: string; submitName: string }
  googleConnect: string
  signOut: string
  googleAccount: { selector: string; providerText: string }
}

export function createBrowserApp(
  baseURL: string,
  ui: BrowserUI,
): Omit<App, "seedPasswordUser" | "facts"> {
  const app: Omit<App, "seedPasswordUser" | "facts"> = {
    baseURL,
    googleCallbackUrl: `${baseURL}/auth/google/callback`,

    async startGoogleSignIn(page) {
      await page.goto(`${baseURL}/`)
      await page
        .getByRole(ui.googleSignIn.role, {
          name: ui.googleSignIn.name,
          exact: true,
        })
        .click()
    },

    async signInWithPassword(page, email, password) {
      await page.goto(`${baseURL}${ui.routes.signIn}`)
      await page.getByLabel(ui.password.identifierLabel).fill(email)
      await page.getByLabel("Password").fill(password)
      await page
        .getByRole("button", { name: ui.password.submitName, exact: true })
        .click()
    },

    async startGoogleConnect(page) {
      await page
        .getByRole("button", { name: ui.googleConnect, exact: true })
        .click()
    },

    async disconnectGoogle(page, providerEmail) {
      await app
        .googleAccount(page, providerEmail)
        .getByRole("button", { name: "Disconnect", exact: true })
        .click()
    },

    async signOut(page) {
      await page.getByRole("button", { name: ui.signOut, exact: true }).click()
      await expect(
        page.getByRole(ui.googleSignIn.role, {
          name: ui.googleSignIn.name,
          exact: true,
        }),
      ).toBeVisible()
    },

    async gotoProfile(page) {
      await page.goto(`${baseURL}${ui.routes.profile}`)
    },

    profileHeading(page, email) {
      return page.getByRole("heading", { level: 1, name: email, exact: true })
    },

    googleAccount(page, providerEmail) {
      return page
        .locator(ui.googleAccount.selector)
        .filter({ hasText: ui.googleAccount.providerText })
        .filter({ hasText: providerEmail })
    },

    async expectSignedOut(page) {
      await app.gotoProfile(page)
      await expect(page).toHaveURL(`${baseURL}${ui.routes.signIn}`)
      await expect(page.getByLabel(ui.password.identifierLabel)).toBeVisible()
    },
  }
  return app
}
