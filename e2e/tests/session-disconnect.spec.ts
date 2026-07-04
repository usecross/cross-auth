import { expect, test } from "@playwright/test"

import { completeGitHubMockSignIn } from "./helpers/auth.js"

test("backend profile disconnects a social account when a password remains", async ({
  page,
}) => {
  await page.goto("http://127.0.0.1:8000/")

  // A dedicated password account keeps a password (so disconnecting GitHub is
  // allowed) and its GitHub connection stays isolated from the shared demo user.
  await page.getByLabel("Email").fill("connect-demo@example.com")
  await page.getByLabel("Password").fill("password123")
  await page.getByRole("button", { name: "Sign in with password" }).click()

  await expect(page).toHaveURL(/127\.0\.0\.1:8000\/profile/)

  await page.getByRole("link", { name: "Connect GitHub (session)" }).click()
  await completeGitHubMockSignIn(
    page,
    "connect-demo@example.com",
    /127\.0\.0\.1:8000\/profile/,
  )

  const account = page
    .locator("li[data-social-account-id]")
    .filter({ hasText: "connect-demo@example.com" })
    .first()
  await expect(account.getByRole("button", { name: "Disconnect" })).toBeVisible()

  const [deleteResponse] = await Promise.all([
    page.waitForResponse(
      (response) =>
        response.request().method() === "DELETE" &&
        response.url().includes("/auth/github/social-accounts/"),
    ),
    account.getByRole("button", { name: "Disconnect" }).click(),
  ])
  expect(deleteResponse.status()).toBe(200)

  // The button reloads /profile on success.
  await expect(page).toHaveURL(/127\.0\.0\.1:8000\/profile/)
})

test("backend profile refuses to disconnect the only login method", async ({
  page,
}) => {
  // A fresh email creates a GitHub-only user (no password), so GitHub is the
  // only login method and the disconnect guard must reject the request.
  const email = `guard-${Date.now()}-${Math.random().toString(16).slice(2)}@example.com`

  await page.goto("http://127.0.0.1:8000/")
  await page.getByRole("link", { name: "Continue with GitHub" }).click()
  await completeGitHubMockSignIn(page, email, /127\.0\.0\.1:8000\/profile/)

  await expect(page.getByRole("heading", { name: email })).toBeVisible()

  const account = page
    .locator("li[data-social-account-id]")
    .filter({ hasText: "github" })
    .first()
  await expect(account.getByText("login method")).toBeVisible()

  const [deleteResponse] = await Promise.all([
    page.waitForResponse(
      (response) =>
        response.request().method() === "DELETE" &&
        response.url().includes("/auth/github/social-accounts/"),
    ),
    account.getByRole("button", { name: "Disconnect" }).click(),
  ])
  expect(deleteResponse.status()).toBe(400)

  await expect(page.locator("#disconnect-status")).toContainText(
    "only login method",
  )
  // The account stays connected because the disconnect was refused.
  await expect(account).toBeVisible()
})
