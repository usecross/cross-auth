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

// How the shared scenarios drive one framework's example app. Drivers map
// steps to the app's own pages, forms and storage; the scenarios, and every
// assertion about authentication outcomes, live in frameworks/contract.
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

  seedPasswordUser(email: string, password: string): Promise<void>
  facts(email: string): Promise<AccountFacts>
}

export interface Framework {
  // Worker N serves on basePort + N.
  readonly basePort: number
  start(options: {
    port: number
    dataDir: string
    logFile: string
  }): Promise<App & { stop(): Promise<void> }>
}
