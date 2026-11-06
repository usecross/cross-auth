import { expect, test } from "./helpers/fixtures.js"

import { completeGitHubMockSignIn } from "./helpers/auth.js"

test("backend profile disconnects a social account when a password remains", async ({
  page, backend, spa, socialIdentity,
}) => {
  await page.goto(`${backend}/`)

  await page.getByLabel("Email").fill("demo@example.com")
  await page.getByLabel("Password").fill("password123")
  await page.getByRole("button", { name: "Sign in with password" }).click()

  await expect(page).toHaveURL(`${backend}/profile`)

  await page.getByRole("link", { name: "Connect GitHub (session)" }).click()
  await completeGitHubMockSignIn(
    page,
    socialIdentity.email,
    `${backend}/profile`,
  )

  const account = page
    .locator("li[data-social-account-id]")
    .filter({ hasText: socialIdentity.email })
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

  await expect(account).toHaveCount(0)
  const me = await page.request.get(`${backend}/api/me`)
  expect(await me.json()).toMatchObject({ email: "demo@example.com", social_accounts: [] })
})

test("backend profile refuses to disconnect the only login method", async ({
  page, backend, spa, socialIdentity,
}) => {
  // A fresh email creates a GitHub-only user (no password), so GitHub is the
  // only login method and the disconnect guard must reject the request.
  const email = socialIdentity.email

  await page.goto(`${backend}/`)
  await page.getByRole("link", { name: "Continue with GitHub" }).click()
  await completeGitHubMockSignIn(page, email, `${backend}/profile`)

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
