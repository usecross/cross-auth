import { expect, type Page } from "@playwright/test"

import type { App } from "./app.js"
import { currentStep, totp } from "./totp.js"

// Only the example apps' routes and UI labels differ. Browser actions and
// profile/session checks are implemented once below, not in each framework.
interface BrowserUI {
  routes: { signIn: string; profile: string; twoFactor: string }
  googleSignIn: { role: "button" | "link"; name: string }
  password: { identifierLabel: string; submitName: string }
  googleConnect: string
  signOut: string
  googleAccount: { selector: string; providerText: string }
}

type BrowserApp = Omit<App, "seedPasswordUser" | "setActive" | "facts">

export function createBrowserApp(
  baseURL: string,
  ui: BrowserUI,
): BrowserApp {
  const app: BrowserApp = {
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

    async gotoTwoFactorSettings(page) {
      await page.goto(`${baseURL}${ui.routes.twoFactor}`)
    },

    twoFactorStatus(page) {
      return page.getByTestId("mfa-status")
    },

    recoveryCodesRemaining(page) {
      return page.getByTestId("recovery-codes-remaining")
    },

    async enrollTotp(page) {
      await app.gotoTwoFactorSettings(page)
      await page
        .getByRole("button", { name: "Set up an authenticator app", exact: true })
        .click()
      // The QR code is rendered by the app itself, as an inline SVG.
      await expect(page.getByTestId("totp-qr").locator("svg")).toBeVisible()
      const secret = (await page.getByTestId("totp-secret").textContent())?.trim()
      if (!secret) throw new Error("The enrollment page showed no key")
      const step = currentStep()
      await page
        .getByLabel("Code from your authenticator app")
        .fill(totp(secret, step))
      await page.getByRole("button", { name: "Turn on", exact: true }).click()
      const recoveryCodes = await readRecoveryCodes(page)
      await page.getByRole("link", { name: "I saved them", exact: true }).click()
      return { secret, step, recoveryCodes }
    },

    async enterSignInCode(page, code) {
      const field = page.getByLabel("Code from your authenticator app")
      await field.fill(code)
      await page
        .locator("form")
        .filter({ has: field })
        .getByRole("button", { name: "Verify", exact: true })
        .click()
    },

    async enterRecoveryCode(page, code) {
      await page.getByText("Use a recovery code", { exact: true }).click()
      const field = page.getByLabel("Recovery code", { exact: true })
      await field.fill(code)
      await page
        .locator("form")
        .filter({ has: field })
        .getByRole("button", { name: "Verify", exact: true })
        .click()
    },

    async regenerateRecoveryCodes(page) {
      await app.gotoTwoFactorSettings(page)
      await page
        .getByRole("button", { name: "Regenerate recovery codes", exact: true })
        .click()
      const codes = await readRecoveryCodes(page)
      await page.getByRole("link", { name: "I saved them", exact: true }).click()
      return codes
    },

    async removeTwoFactor(page) {
      await app.gotoTwoFactorSettings(page)
      await page
        .getByTestId("mfa-factor")
        .getByRole("button", { name: "Remove", exact: true })
        .click()
    },

    async expectSignedOut(page) {
      await app.gotoProfile(page)
      await expect(page).toHaveURL(`${baseURL}${ui.routes.signIn}`)
      await expect(page.getByLabel(ui.password.identifierLabel)).toBeVisible()
    },
  }
  return app
}

async function readRecoveryCodes(page: Page): Promise<string[]> {
  const list = page.getByTestId("recovery-codes").locator("li")
  await expect(list.first()).toBeVisible()
  return (await list.allTextContents()).map((code) => code.trim())
}
