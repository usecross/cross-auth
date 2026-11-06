import { expect, test } from "./helpers/fixtures.js"

import { completeGitHubMockSignIn } from "./helpers/auth.js"

test("SPA lists a social account and surfaces the disconnect guard", async ({
  page, backend, spa, socialIdentity,
}) => {
  await page.goto(`${spa}/`)

  // A fresh email makes a GitHub-only user, so GitHub is the only login method
  // and the disconnect guard rejects the bearer DELETE.
  const email = socialIdentity.email

  await page.getByRole("button", { name: "Log in with GitHub" }).click()
  await completeGitHubMockSignIn(page, email)

  await expect(page).toHaveURL(`${spa}/`)
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
