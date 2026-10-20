import { expect, test } from "../support/fixtures.js"
import { chooseGoogleAccount } from "../support/google.js"

// FastAPI-only: GET /auth/{provider}/connect attaches an integration-only
// connection. It never becomes a way to sign in (see docs/oauth.md); Django's
// integration only offers login-enabled linking.
test("a session connect adds Google without making it a way to sign in", async ({
  app,
  page,
  googleUser,
}) => {
  const user = googleUser("integration")
  const password = "correct-horse-battery-staple"
  await app.seedPasswordUser(user.email, password)
  const [native] = (await app.facts(user.email)).users

  await app.signInWithPassword(page, user.email, password)
  await page.getByRole("link", { name: "Connect Google (session)" }).click()
  await chooseGoogleAccount(page, user)
  await expect(app.googleAccount(page, user.email)).toBeVisible()
  await expect(
    app.googleAccount(page, user.email).getByText("login method"),
  ).toHaveCount(0)
  const connected = await app.facts(user.email)
  expect(connected.google_accounts).toEqual([
    {
      user_id: native.id,
      provider_user_id: expect.any(String),
      provider_email: user.email,
    },
  ])

  await app.signOut(page)
  await app.startGoogleSignIn(page)
  const callback = page.waitForResponse((response) =>
    response.url().startsWith(app.googleCallbackUrl),
  )
  await chooseGoogleAccount(page, user)
  expect((await callback).status()).toBe(400)
  expect(await (await callback).json()).toMatchObject({
    error: "access_denied",
  })
  await app.expectSignedOut(page)
  expect(await app.facts(user.email)).toEqual(connected)
})
