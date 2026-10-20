import { expect, type Page } from "@playwright/test"
import type { SeedConfig } from "emulate"

// Dummy credentials that only the local emulator accepts.
export const GOOGLE_CLIENT_ID = "cross-auth-e2e.apps.googleusercontent.com"
export const GOOGLE_CLIENT_SECRET = "GOCSPX-cross-auth-e2e"

// Each framework app runs one server per Playwright worker on
// basePort + parallelIndex, so the OAuth client allows that many callbacks.
export const MAX_WORKERS = 8
// Emulator users must exist before the run starts, so every identity a
// scenario uses is declared here. Each --repeat-each run gets its own copy.
export const MAX_REPEATS = 3

const IDENTITIES = {
  signup: { verified: true },
  returning: { verified: true },
  connect: { verified: true },
  disconnect: { verified: true },
  "last-method": { verified: true },
  integration: { verified: true },
  unverified: { verified: false },
  // Both example apps refuse sign-ins from this domain before writing.
  denied: { verified: true, domain: "blocked.example" },
} satisfies Record<string, { verified: boolean; domain?: string }>

export type IdentityName = keyof typeof IDENTITIES

export interface GoogleIdentity {
  email: string
  name: string
}

export function googleIdentity(
  name: IdentityName,
  repeat: number,
): GoogleIdentity {
  if (repeat >= MAX_REPEATS) {
    throw new Error(
      `The Google emulator seeds at most ${MAX_REPEATS} repeats (--repeat-each)`,
    )
  }
  const { domain = "e2e.test" } = IDENTITIES[name] as { domain?: string }
  return { email: `${name}.${repeat}@${domain}`, name: `E2E ${name} ${repeat}` }
}

export function googleSeed(callbackUrls: string[]): SeedConfig {
  const users = Object.entries(IDENTITIES).flatMap(([name, { verified }]) =>
    Array.from({ length: MAX_REPEATS }, (_, repeat) => ({
      ...googleIdentity(name as IdentityName, repeat),
      email_verified: verified,
    })),
  )
  return {
    google: {
      users,
      oauth_clients: [
        {
          client_id: GOOGLE_CLIENT_ID,
          client_secret: GOOGLE_CLIENT_SECRET,
          name: "Cross Auth E2E",
          redirect_uris: callbackUrls,
        },
      ],
    },
  }
}

export function emulatorUrl(): string {
  const url = process.env.GOOGLE_EMULATOR_URL
  if (!url) throw new Error("GOOGLE_EMULATOR_URL is set by the global setup")
  return url
}

// Picks the account on the emulator's sign-in page, which posts back and
// redirects the browser to the app's callback.
export async function chooseGoogleAccount(
  page: Page,
  identity: GoogleIdentity,
): Promise<void> {
  const signInPage = `${emulatorUrl()}/o/oauth2/v2/auth?`
  await expect(page).toHaveURL((url) => url.href.startsWith(signInPage))
  // One form per seeded user; its hidden email field names the account.
  await page
    .locator("form")
    .filter({
      has: page.locator(`input[name="email"][value="${identity.email}"]`),
    })
    .getByRole("button")
    .click()
}
