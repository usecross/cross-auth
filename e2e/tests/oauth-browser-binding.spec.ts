import { expect, test } from "@playwright/test"

const backend = "http://127.0.0.1:8000"

test("OAuth callback cannot be transferred to another browser", async ({ context, browser }) => {
  const start = await context.request.get(`${backend}/auth/github/login`, { maxRedirects: 0 })
  const state = new URL(start.headers().location).searchParams.get("state")
  const callback = `${backend}/auth/github/callback?state=${state}&error=access_denied`
  const other = await browser.newContext()

  try {
    const foreignPage = await other.newPage()
    const rejected = await foreignPage.goto(callback)
    expect(rejected?.status()).toBe(400)
    expect(await rejected?.json()).toMatchObject({ error: "invalid_request" })

    // The wrong browser did not consume the original attempt.
    const originalPage = await context.newPage()
    const accepted = await originalPage.goto(callback)
    expect(await accepted?.json()).toMatchObject({ error: "access_denied" })
    expect((await context.cookies()).some(cookie => cookie.name.includes("cross_auth_oauth_"))).toBe(false)
  } finally {
    await other.close()
  }
})

test("cross-site form POST resumes with the browser's Lax cookie", async ({ context, page }) => {
  const start = await context.request.get(`${backend}/auth/github/login`, { maxRedirects: 0 })
  const state = new URL(start.headers().location).searchParams.get("state")
  const callback = `${backend}/auth/github/callback?state=${state}&error=access_denied`

  // The synthetic provider returns an error, avoiding a remote token exchange.
  // GitHub's parser reads the query; Apple form parsing is tested in Python.
  await page.route("http://provider.example/authorize", route => route.fulfill({
    contentType: "text/html",
    body: `<form method="post" action="${callback}"><button>Continue</button></form>`,
  }))
  await page.goto("http://provider.example/authorize")
  const posted = page.waitForRequest(request => request.method() === "POST" && request.url().startsWith(callback))
  const completed = page.waitForResponse(response => response.url().includes("/callback?resume="))
  await page.getByRole("button", { name: "Continue" }).click()

  const postHeaders = await (await posted).allHeaders()
  expect(postHeaders.cookie ?? "").not.toContain("cross_auth_oauth_")
  const response = await completed
  expect(response.status()).toBe(400)
  expect(await response.json()).toMatchObject({ error: "access_denied" })
  expect((await context.cookies()).some(cookie => cookie.name.includes("cross_auth_oauth_"))).toBe(false)
})
