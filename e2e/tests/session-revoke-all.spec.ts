import { expect, test } from "./helpers/fixtures.js"

import { completeGitHubMockSignIn } from "./helpers/auth.js"

test("logging out everywhere ends the current session", async ({ page, backend, spa, socialIdentity }) => {
  const email = socialIdentity.email

  await page.goto(`${backend}/`)
  await page.getByRole("link", { name: "Continue with GitHub" }).click()
  await completeGitHubMockSignIn(page, email, `${backend}/profile`)

  await page
    .locator(".header-nav")
    .getByRole("link", { name: "Sessions", exact: true })
    .click()
  await expect(
    page.getByRole("heading", { name: `Active sessions for ${email}` }),
  ).toBeVisible()

  // Revokes every session (including this one) and clears the cookie.
  await Promise.all([
    page.waitForURL(`${backend}/`),
    page.getByRole("button", { name: "Log out everywhere" }).click(),
  ])

  // The current session is gone, so a protected page redirects home.
  await page.goto(`${backend}/profile`)
  await expect(page).toHaveURL(`${backend}/`)
})
