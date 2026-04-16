import { expect, test } from "@playwright/test"

import { completeGitHubMockSignIn } from "./helpers/auth.js"

test("session connect attaches GitHub to an already-logged-in user", async ({
  page,
}) => {
  await page.goto("http://127.0.0.1:8000/")

  // Log in with password so we have a session cookie.
  await page.getByLabel("Email").fill("demo@example.com")
  await page.getByLabel("Password").fill("password123")
  await page.getByRole("button", { name: "Sign in with password" }).click()

  await expect(page).toHaveURL(/127\.0\.0\.1:8000\/profile/)

  // Click the session-mode connect link. Unlike "Link GitHub account"
  // (which runs a PKCE round-trip via POST /link + /finalize-link), this
  // is a plain GET to /auth/github/connect — single round-trip, cookie
  // stays on the server the whole time.
  await page.getByRole("link", { name: "Connect GitHub (session)" }).click()

  await completeGitHubMockSignIn(
    page,
    "demo@example.com",
    /127\.0\.0\.1:8000\/profile/,
  )

  await expect(page).toHaveURL(/127\.0\.0\.1:8000\/profile/)
  await expect(
    page.getByRole("heading", { name: "demo@example.com" }),
  ).toBeVisible()
  await expect(page.getByText("provider user")).toBeVisible()
})
