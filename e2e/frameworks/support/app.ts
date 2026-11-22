import type { Locator, Page } from "@playwright/test"

// What the database says about one email: native users with that email, and
// Google identities owned by them or reporting that provider email.
export interface AccountFacts {
  users: { id: string; has_password: boolean }[]
  google_accounts: {
    user_id: string
    provider_user_id: string
    provider_email: string | null
  }[]
}

// How the shared scenarios drive an example app. support/browser.ts supplies
// the browser actions from each framework's route/locator configuration.
// Framework drivers supply native storage setup/reads; scenarios live in
// frameworks/contract.
export interface App {
  readonly baseURL: string
  readonly googleCallbackUrl: string

  // Starts Google sign-in from the signed-out home page.
  startGoogleSignIn(page: Page): Promise<void>
  // Signs in with the app's native password login.
  signInWithPassword(page: Page, email: string, password: string): Promise<void>
  // Starts connecting Google from the signed-in profile page.
  startGoogleConnect(page: Page): Promise<void>
  disconnectGoogle(page: Page, providerEmail: string): Promise<void>
  signOut(page: Page): Promise<void>

  gotoProfile(page: Page): Promise<void>
  // The signed-in profile page for this user.
  profileHeading(page: Page, email: string): Locator
  googleAccount(page: Page, providerEmail: string): Locator
  // Asserts the browser has no session: the profile sends it to sign in.
  expectSignedOut(page: Page): Promise<void>

  // Two-factor authentication, through the example's settings pages and the
  // verify step at sign-in. Both examples use the same labels.
  gotoTwoFactorSettings(page: Page): Promise<void>
  twoFactorStatus(page: Page): Locator
  recoveryCodesRemaining(page: Page): Locator
  // Scans nothing: reads the key shown next to the QR code, confirms the
  // first code and returns the recovery codes shown once.
  enrollTotp(page: Page): Promise<TwoFactorEnrollment>
  enterSignInCode(page: Page, code: string): Promise<void>
  enterRecoveryCode(page: Page, code: string): Promise<void>
  regenerateRecoveryCodes(page: Page): Promise<string[]>
  removeTwoFactor(page: Page): Promise<void>

  seedPasswordUser(email: string, password: string): Promise<void>
  // Suspends (false) or restores (true) the users with this email the way the
  // app's own rule reads it: Django's is_active, or the FastAPI example's
  // column behind user_can_authenticate.
  setActive(email: string, active: boolean): Promise<void>
  facts(email: string): Promise<AccountFacts>
}

// What turning on two-factor authentication showed the user, once.
export interface TwoFactorEnrollment {
  secret: string
  // The TOTP time step whose code confirmed it; that code is spent.
  step: number
  recoveryCodes: string[]
}

export interface Framework {
  start(options: {
    port: number
    dataDir: string
    logFile: string
    env?: Record<string, string>
  }): Promise<App & { stop(): Promise<void> }>
}
