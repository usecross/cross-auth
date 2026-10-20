import { expect, test } from "../support/fixtures.js"
import { chooseGoogleAccount } from "../support/google.js"

test("a new Google user is signed up and stays signed in", async ({
  app,
  page,
  googleUser,
}) => {
  const user = googleUser("signup")

  await app.startGoogleSignIn(page)
  await chooseGoogleAccount(page, user)
  await expect(app.profileHeading(page, user.email)).toBeVisible()

  await page.reload()
  await expect(app.profileHeading(page, user.email)).toBeVisible()
  await expect(app.googleAccount(page, user.email)).toBeVisible()

  const facts = await app.facts(user.email)
  expect(facts.users).toEqual([{ id: expect.any(String), has_password: false }])
  expect(facts.google_accounts).toEqual([
    {
      user_id: facts.users[0].id,
      provider_user_id: expect.any(String),
      provider_email: user.email,
    },
  ])
})

test("a returning Google user signs in to the same user", async ({
  app,
  page,
  googleUser,
}) => {
  const user = googleUser("returning")

  await app.startGoogleSignIn(page)
  await chooseGoogleAccount(page, user)
  await expect(app.profileHeading(page, user.email)).toBeVisible()
  const first = await app.facts(user.email)

  await app.signOut(page)
  await app.expectSignedOut(page)

  await app.startGoogleSignIn(page)
  await chooseGoogleAccount(page, user)
  await expect(app.profileHeading(page, user.email)).toBeVisible()
  expect(await app.facts(user.email)).toEqual(first)
})

test("an app policy refuses a new identity before anything is written", async ({
  app,
  page,
  googleUser,
}) => {
  // Each example refuses this domain from its pre-write callback hook.
  const user = googleUser("denied")

  await app.startGoogleSignIn(page)
  const callback = page.waitForResponse((response) =>
    response.url().startsWith(app.googleCallbackUrl),
  )
  await chooseGoogleAccount(page, user)
  expect((await callback).status()).toBe(403)

  await app.expectSignedOut(page)
  expect(await app.facts(user.email)).toEqual({
    users: [],
    google_accounts: [],
  })
})

test("an unverified Google email cannot sign up", async ({
  app,
  page,
  googleUser,
}) => {
  const user = googleUser("unverified")

  await app.startGoogleSignIn(page)
  const callback = page.waitForResponse((response) =>
    response.url().startsWith(app.googleCallbackUrl),
  )
  await chooseGoogleAccount(page, user)
  // Which check answers first, and so the status, is the app's choice.
  expect((await callback).status()).toBeGreaterThanOrEqual(400)
  expect((await callback).status()).toBeLessThan(500)

  await app.expectSignedOut(page)
  expect(await app.facts(user.email)).toEqual({
    users: [],
    google_accounts: [],
  })
})
