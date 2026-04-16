import { expect, test } from "@playwright/test"

import { completeGitHubMockSignIn } from "./helpers/auth"

test("session account linking succeeds from the FastAPI UI", async ({ page }) => {
  await page.goto("http://127.0.0.1:8000/")

  await page.getByLabel("Email").fill("demo@example.com")
  await page.getByLabel("Password").fill("password123")
  await page.getByRole("button", { name: "Sign in with password" }).click()

  await expect(page).toHaveURL(/127\.0\.0\.1:8000\/profile/)
  await page.getByRole("button", { name: "Link GitHub account" }).click()

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
