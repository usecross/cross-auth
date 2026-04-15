import { expect, test } from "@playwright/test"

async function completeGitHubMockSignIn(page, email) {
  await expect(page).toHaveURL(/github-oauth-mock.*\/login\/oauth\/authorize/)
  await page.getByLabel("Email address").fill(email)
  await page.getByRole("button", { name: "Sign in" }).click()
}

test("session social login succeeds on the FastAPI backend", async ({ page }) => {
  await page.goto("http://127.0.0.1:8000/")

  await page.getByRole("link", { name: "Continue with GitHub" }).click()
  await completeGitHubMockSignIn(page, "demo@example.com")

  await expect(page).toHaveURL(/127\.0\.0\.1:8000\/profile/)
  await expect(
    page.getByRole("heading", { name: "demo@example.com" }),
  ).toBeVisible()
  await expect(page.getByText("provider user")).toBeVisible()
})

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
