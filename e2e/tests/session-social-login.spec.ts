import { expect, test } from "@playwright/test"

import { completeGitHubMockSignIn } from "./helpers/auth.js"

test("session social login succeeds", async ({ page }) => {
  await page.goto("http://127.0.0.1:8000/")

  await page.getByRole("link", { name: "Continue with GitHub" }).click()
  await completeGitHubMockSignIn(
    page,
    "demo@example.com",
    /127\.0\.0\.1:8000\/profile/,
  )

  await expect(page).toHaveURL(/127\.0\.0\.1:8000\/profile/)
  await expect(
    page.getByRole("heading", { name: "demo@example.com" }),
  ).toBeVisible()
  await expect(page.getByText("provider user")).toBeVisible()
})
