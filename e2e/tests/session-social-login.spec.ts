import { expect, test } from "@playwright/test"

import { completeGitHubMockSignIn } from "./helpers/auth.js"

test("session social login succeeds", async ({ page }) => {
  // Keep this identity separate from tests that connect accounts without login.
  const email = `session-login-${Date.now()}-${Math.random().toString(16).slice(2)}@example.com`

  await page.goto("http://127.0.0.1:8000/")

  await page.getByRole("link", { name: "Continue with GitHub" }).click()
  await completeGitHubMockSignIn(
    page,
    email,
    /127\.0\.0\.1:8000\/profile/,
  )

  await expect(page).toHaveURL(/127\.0\.0\.1:8000\/profile/)
  await expect(page.getByRole("heading", { name: email })).toBeVisible()
  await expect(page.getByText("provider user")).toBeVisible()
})
