import { expect, test } from "@playwright/test"

import { completeGitHubMockSignIn } from "./helpers/auth.js"

test("SPA lists a social account and surfaces the disconnect guard", async ({
  page,
}) => {
  await page.goto("http://127.0.0.1:5173/")

  // A fresh email makes a GitHub-only user, so GitHub is the only login method
  // and the disconnect guard rejects the bearer DELETE.
  const email = `spa-accounts-${Date.now()}-${Math.random().toString(16).slice(2)}@example.com`

  await page.getByRole("button", { name: "Log in with GitHub" }).click()
  await completeGitHubMockSignIn(page, email)

  await expect(page).toHaveURL("http://127.0.0.1:5173/")
  await expect(page.getByText("token present")).toBeVisible()

  const panel = page.getByTestId("accounts-panel")
  await expect(panel).toBeVisible()
  await expect(panel.getByText("github")).toBeVisible()
  await expect(panel.getByText("login method")).toBeVisible()

  const disconnect = panel.getByRole("button", { name: "Disconnect" }).first()
  const [deleteResponse] = await Promise.all([
    page.waitForResponse(
      (response) =>
        response.request().method() === "DELETE" &&
        response.url().includes("/auth/github/social-accounts/"),
    ),
    disconnect.click(),
  ])
  expect(deleteResponse.status()).toBe(400)

  await expect(page.locator(".notice")).toContainText("only login method")
})
