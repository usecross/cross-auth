import type { Page } from "@playwright/test"

import type { App } from "../support/app.js"
import { expect, test } from "../support/fixtures.js"
import { chooseGoogleAccount, type GoogleIdentity } from "../support/google.js"
import { totp } from "../support/totp.js"

const WRONG_CODE = "That code is not correct"

async function signInWithGoogle(app: App, page: Page, user: GoogleIdentity) {
  await app.startGoogleSignIn(page)
  await chooseGoogleAccount(page, user)
}

// Google alone no longer signs the user in: the browser waits on the
// app's verify step, and the profile is still out of reach.
async function expectWaitingForCode(app: App, page: Page, user: GoogleIdentity) {
  await expect(page.getByRole("heading", { name: "Two-factor authentication" })).toBeVisible()
  await expect(page.getByLabel("Code from your authenticator app")).toBeVisible()
  await expect(app.profileHeading(page, user.email)).toHaveCount(0)
}

test("a user turns on 2FA, signs in with codes and recovery codes, and turns it off", async ({
  app,
  page,
  googleUser,
}) => {
  // Two settings visits and five sign-ins through the emulator.
  test.setTimeout(90_000)
  const user = googleUser("two-factor")

  // Enroll, right after signing in (a fresh sign-in allows 2FA changes).
  await signInWithGoogle(app, page, user)
  await expect(app.profileHeading(page, user.email)).toBeVisible()
  await app.gotoProfile(page)
  await page.getByRole("link", { name: "Two-factor authentication", exact: true }).click()
  await expect(app.twoFactorStatus(page)).toHaveText("Two-factor authentication is off.")

  const enrollment = await app.enrollTotp(page)
  expect(enrollment.recoveryCodes).toHaveLength(10)
  expect(new Set(enrollment.recoveryCodes).size).toBe(10)
  await expect(app.twoFactorStatus(page)).toHaveText("Two-factor authentication is on.")
  await expect(app.recoveryCodesRemaining(page)).toHaveText("10 recovery codes left.")

  // Sign out, then sign in with a code.
  await app.gotoProfile(page)
  await app.signOut(page)
  await app.expectSignedOut(page)
  await signInWithGoogle(app, page, user)
  await expectWaitingForCode(app, page, user)

  await app.enterSignInCode(page, "000000")
  await expect(page.getByRole("alert")).toContainText(WRONG_CODE)
  // The code that confirmed enrollment is spent.
  await app.enterSignInCode(page, totp(enrollment.secret, enrollment.step))
  await expect(page.getByRole("alert")).toContainText(WRONG_CODE)
  await expect(app.profileHeading(page, user.email)).toHaveCount(0)

  await app.enterSignInCode(page, totp(enrollment.secret, enrollment.step + 1))
  await expect(app.profileHeading(page, user.email)).toBeVisible()

  // Sign in with a recovery code instead.
  await app.signOut(page)
  await signInWithGoogle(app, page, user)
  await expectWaitingForCode(app, page, user)
  await app.enterRecoveryCode(page, enrollment.recoveryCodes[0])
  await expect(app.profileHeading(page, user.email)).toBeVisible()
  await app.gotoTwoFactorSettings(page)
  await expect(app.recoveryCodesRemaining(page)).toHaveText("9 recovery codes left.")

  // Regenerate: new codes replace every old one.
  const regenerated = await app.regenerateRecoveryCodes(page)
  expect(regenerated).toHaveLength(10)
  expect(regenerated.filter((code) => enrollment.recoveryCodes.includes(code))).toEqual([])
  await expect(app.recoveryCodesRemaining(page)).toHaveText("10 recovery codes left.")

  await app.gotoProfile(page)
  await app.signOut(page)
  await signInWithGoogle(app, page, user)
  await expectWaitingForCode(app, page, user)
  await app.enterRecoveryCode(page, enrollment.recoveryCodes[1])
  await expect(page.getByRole("alert")).toContainText(WRONG_CODE)
  await app.enterRecoveryCode(page, regenerated[0])
  await expect(app.profileHeading(page, user.email)).toBeVisible()

  // Remove the authenticator: 2FA is off, and Google signs in alone again.
  await app.removeTwoFactor(page)
  await expect(app.twoFactorStatus(page)).toHaveText("Two-factor authentication is off.")

  await app.gotoProfile(page)
  await app.signOut(page)
  await signInWithGoogle(app, page, user)
  await expect(app.profileHeading(page, user.email)).toBeVisible()
})
