import { expect, test } from "./helpers/fixtures.js"

import { completeGitHubMockSignIn } from "./helpers/auth.js"

test("session social login succeeds", async ({ page, backend, spa, socialIdentity }) => {
  // Keep this identity separate from tests that connect accounts without login.
  const email = socialIdentity.email

  await page.goto(`${backend}/`)

  await page.getByRole("link", { name: "Continue with GitHub" }).click()
  await completeGitHubMockSignIn(
    page,
    email,
    `${backend}/profile`,
  )

  await expect(page).toHaveURL(`${backend}/profile`)
  await expect(page.getByRole("heading", { name: email })).toBeVisible()
  await expect(page.getByText("provider user")).toBeVisible()
})
