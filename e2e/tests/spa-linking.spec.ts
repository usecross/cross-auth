import { expect, test } from "./helpers/fixtures.js"

import { completeGitHubMockSignIn } from "./helpers/auth.js"

test("GitHub account linking succeeds from the SPA UI", async ({ page, backend, spa, socialIdentity }) => {
  await page.goto(`${spa}/`)

  await page.getByRole("button", { name: "Log in with password" }).click()
  await expect(page.getByText("token present")).toBeVisible()
  await expect(page.getByText('"email": "demo@example.com"')).toBeVisible()

  await page.getByRole("button", { name: "Link GitHub account" }).click()

  await completeGitHubMockSignIn(page, socialIdentity.email, `${spa}/`)

  await expect(page).toHaveURL(`${spa}/`)
  await expect(page.getByText(`"provider_user_id": "${socialIdentity.id}"`)).toBeVisible()
  await expect(page.getByText(`"provider_email": "${socialIdentity.email}"`)).toBeVisible()
  await expect(page.getByText('"is_login_method": true')).toBeVisible()
  await expect(page.getByText('"email": "demo@example.com"')).toBeVisible()
})
