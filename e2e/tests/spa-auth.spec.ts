import { expect, test } from "@playwright/test"

import { completeGitHubMockSignIn } from "./helpers/auth"

test("separate SPA completes auth-code flow and calls bearer API", async ({
  page,
}) => {
  await page.goto("http://127.0.0.1:5173/")

  await page.getByRole("button", { name: "Log in with GitHub" }).click()
  await completeGitHubMockSignIn(page, "demo@example.com")

  await expect(page).toHaveURL("http://127.0.0.1:5173/")
  await expect(page.getByText("token present")).toBeVisible()
  await expect(page.getByText('"email": "demo@example.com"')).toBeVisible()
  await expect(page.getByText('"provider": "github"')).toBeVisible()
})
