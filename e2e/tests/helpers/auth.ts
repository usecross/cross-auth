import { expect, type Page } from "@playwright/test"

export async function completeGitHubMockSignIn(
  page: Page,
  email: string,
  expectedUrlPattern: RegExp | string | null = null,
): Promise<void> {
  await expect(page).toHaveURL(/github-oauth-mock.*\/login\/oauth\/authorize/)
  await page.getByLabel("Email address").fill(email)

  if (expectedUrlPattern) {
    await Promise.all([
      page.waitForURL(expectedUrlPattern, { timeout: 15_000 }),
      page.getByRole("button", { name: "Sign in" }).click(),
    ])
    return
  }

  await page.getByRole("button", { name: "Sign in" }).click()
}
