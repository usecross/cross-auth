import { expect, test } from "@playwright/test"

import { completeGitHubMockSignIn } from "./helpers/auth.js"

test("logging out everywhere ends the current session", async ({ page }) => {
  // A fresh user keeps its sessions isolated from the shared demo account.
  const email = `revoke-${Date.now()}-${Math.random().toString(16).slice(2)}@example.com`

  await page.goto("http://127.0.0.1:8000/")
  await page.getByRole("link", { name: "Continue with GitHub" }).click()
  await completeGitHubMockSignIn(page, email, /127\.0\.0\.1:8000\/profile/)

  await page
    .locator(".header-nav")
    .getByRole("link", { name: "Sessions", exact: true })
    .click()
  await expect(
    page.getByRole("heading", { name: `Active sessions for ${email}` }),
  ).toBeVisible()

  // Revokes every session (including this one) and clears the cookie.
  await Promise.all([
    page.waitForURL("http://127.0.0.1:8000/"),
    page.getByRole("button", { name: "Log out everywhere" }).click(),
  ])

  // The current session is gone, so a protected page redirects home.
  await page.goto("http://127.0.0.1:8000/profile")
  await expect(page).toHaveURL("http://127.0.0.1:8000/")
})
