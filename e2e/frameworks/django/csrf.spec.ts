import { expect, test } from "../support/fixtures.js"

// Django-only: the sign-in, link and disconnect views are POSTs that rely on
// CsrfViewMiddleware, so a cross-site form without the token never starts a flow.
test("starting Google sign-in without a CSRF token is refused", async ({
  app,
  page,
}) => {
  await page.goto(`${app.baseURL}/`)
  const response = await page.request.post(
    `${app.baseURL}/auth/google/login/`,
    {
      form: { next: "/profile/" },
      headers: { Origin: app.baseURL, Referer: `${app.baseURL}/` },
      maxRedirects: 0,
    },
  )
  expect(response.status()).toBe(403)
  expect(response.headers().location).toBeUndefined()
})
