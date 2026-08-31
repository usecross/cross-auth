import { expect, test, type Page } from "@playwright/test"

import { completeGitHubMockSignIn } from "./helpers/auth.js"

async function delayNextUserResponse(page: Page, email: string) {
  let startResponse = () => {}
  const started = new Promise<void>((resolve) => {
    startResponse = resolve
  })
  let releaseResponse = () => {}
  const released = new Promise<void>((resolve) => {
    releaseResponse = resolve
  })
  let finishResponse = () => {}
  const finished = new Promise<void>((resolve) => {
    finishResponse = resolve
  })
  let delayed = false

  await page.route("**/api/me", async (route) => {
    if (delayed) {
      await route.continue()
      return
    }

    delayed = true
    startResponse()
    await released
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ email, social_accounts: [] }),
    })
    finishResponse()
  })

  return { started, releaseResponse, finished }
}

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

test("clearing a token ignores its delayed bearer API response", async ({ page }) => {
  await page.goto("http://127.0.0.1:5173/")
  await page.getByRole("button", { name: "Log in with password" }).click()
  await expect(page.getByText('"email": "demo@example.com"')).toBeVisible()

  const delayedResponse = await delayNextUserResponse(page, "stale@example.com")
  await page.getByRole("button", { name: "Call /api/me" }).click()
  await delayedResponse.started
  await page.getByRole("button", { name: "Clear token" }).click()

  delayedResponse.releaseResponse()
  await delayedResponse.finished
  await page.waitForTimeout(100)

  await expect(page.getByText("no token", { exact: true })).toBeVisible()
  await expect(page.getByText("state: idle")).toBeVisible()
  await expect(page.getByText("No API response yet.")).toBeVisible()
  await expect(page.getByText("stale@example.com")).not.toBeVisible()
})

test("a replaced token ignores the previous token's delayed user", async ({ page }) => {
  await page.goto("http://127.0.0.1:5173/")
  await page.getByRole("button", { name: "Log in with password" }).click()
  await expect(page.getByText('"email": "demo@example.com"')).toBeVisible()
  const previousToken = await page.evaluate(() =>
    window.localStorage.getItem("cross_auth_spa_access_token"),
  )

  const delayedResponse = await delayNextUserResponse(page, "stale@example.com")
  await page.getByRole("button", { name: "Call /api/me" }).click()
  await delayedResponse.started
  await page.getByRole("button", { name: "Log in with password" }).click()

  await expect
    .poll(() =>
      page.evaluate(() =>
        window.localStorage.getItem("cross_auth_spa_access_token"),
      ),
    )
    .not.toBe(previousToken)
  await expect(page.getByText('"email": "demo@example.com"')).toBeVisible()

  delayedResponse.releaseResponse()
  await delayedResponse.finished
  await page.waitForTimeout(100)

  await expect(page.getByText("state: authenticated")).toBeVisible()
  await expect(page.getByText('"email": "demo@example.com"')).toBeVisible()
  await expect(page.getByText("stale@example.com")).not.toBeVisible()
})
