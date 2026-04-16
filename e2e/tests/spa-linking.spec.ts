import { expect, test } from "@playwright/test"

import { completeGitHubMockSignIn } from "./helpers/auth"

test("GitHub account linking succeeds from the SPA UI", async ({ page }) => {
  await page.goto("http://127.0.0.1:5173/")

  await page.getByRole("button", { name: "Log in with password" }).click()
  await expect(page.getByText("token present")).toBeVisible()
  await expect(page.getByText('"email": "demo@example.com"')).toBeVisible()

  await page.getByRole("button", { name: "Link GitHub account" }).click()

  await completeGitHubMockSignIn(page, "demo@example.com", "http://127.0.0.1:5173/")

  await expect(page).toHaveURL("http://127.0.0.1:5173/")
  await expect(page.getByText('"provider": "github"')).toBeVisible()
})
