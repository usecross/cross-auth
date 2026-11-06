import { expect, test } from "./helpers/fixtures.js"

import { completeGitHubMockSignIn } from "./helpers/auth.js"

test("session connect attaches GitHub to an already-logged-in user", async ({
  page, backend, spa, socialIdentity,
}) => {
  await page.goto(`${backend}/`)

  // Log in with password so we have a session cookie.
  await page.getByLabel("Email").fill("demo@example.com")
  await page.getByLabel("Password").fill("password123")
  await page.getByRole("button", { name: "Sign in with password" }).click()

  await expect(page).toHaveURL(`${backend}/profile`)

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
  await expect(account.getByText("login method")).toHaveCount(0)
  const me = await page.request.get(`${backend}/api/me`)
  expect(await me.json()).toMatchObject({
    email: "demo@example.com",
    social_accounts: [{
      provider: "github", provider_user_id: socialIdentity.id,
      provider_email: socialIdentity.email, is_login_method: false,
    }],
  })
})
