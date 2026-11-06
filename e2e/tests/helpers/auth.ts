import { expect, type Page } from "@playwright/test"

export async function completeGitHubMockSignIn(
  page: Page,
  email: string,
  expectedUrlPattern: RegExp | string | null = null,
): Promise<void> {
  await expect(page).toHaveURL(url =>
    ["127.0.0.1", "localhost"].includes(url.hostname) && url.pathname === "/login/oauth/authorize",
  )
  const account = page.locator("form").filter({ hasText: email })
  const submit = account.getByRole("button")
  if (expectedUrlPattern) {
    await Promise.all([
      page.waitForURL(expectedUrlPattern, { timeout: 15_000 }),
      submit.click(),
    ])
    return
  }
  await submit.click()
}
