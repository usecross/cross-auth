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
  // stays on the server the whole time. Assert the request so the link can't
  // silently regress back to the /auth/github/login flow.
  const [connectRequest] = await Promise.all([
    page.waitForRequest(
      (request) =>
        request.method() === "GET" &&
        request.url().includes("/auth/github/connect"),
    ),
    page.getByRole("link", { name: "Connect GitHub (session)" }).click(),
  ])
  expect(connectRequest.url()).toMatch(/\/auth\/github\/connect\?next=(%2F|\/)profile/)

  await completeGitHubMockSignIn(
    page,
    "demo@example.com",
    /127\.0\.0\.1:8000\/profile/,
  )

  await expect(page).toHaveURL(/127\.0\.0\.1:8000\/profile/)
  await expect(
    page.getByRole("heading", { name: "demo@example.com" }),
  ).toBeVisible()
  // .first(): the shared demo user can hold several social accounts when
  // parallel tests each connect GitHub to it.
  await expect(page.getByText("provider user").first()).toBeVisible()
})
