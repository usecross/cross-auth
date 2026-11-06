import { expect, test } from "./helpers/fixtures.js"

import { completeGitHubMockSignIn } from "./helpers/auth.js"

test("session account linking succeeds", async ({ page, backend, spa, socialIdentity }) => {
  await page.goto(`${backend}/`)

  await page.getByLabel("Email").fill("demo@example.com")
  await page.getByLabel("Password").fill("password123")
  await page.getByRole("button", { name: "Sign in with password" }).click()

  await expect(page).toHaveURL(`${backend}/profile`)
  await page.getByRole("button", { name: "Link GitHub account" }).click()

  await completeGitHubMockSignIn(
    page,
    socialIdentity.email,
    `${backend}/profile`,
  )

  await expect(page).toHaveURL(`${backend}/profile`)
  await expect(
    page.getByRole("heading", { name: "demo@example.com" }),
  ).toBeVisible()
  const account = page.locator("li[data-social-account-id]")
  await expect(account).toHaveCount(1)
  await expect(account).toContainText(socialIdentity.email)
  await expect(account).toContainText(`provider user ${socialIdentity.id}`)
  await expect(account.getByText("login method")).toBeVisible()
  const me = await page.request.get(`${backend}/api/me`)
  expect(await me.json()).toMatchObject({
    email: "demo@example.com",
    social_accounts: [{
      provider: "github", provider_user_id: socialIdentity.id,
      provider_email: socialIdentity.email, is_login_method: true,
    }],
  })
})
