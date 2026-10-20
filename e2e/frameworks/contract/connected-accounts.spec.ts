import { expect, test } from "../support/fixtures.js"
import { chooseGoogleAccount } from "../support/google.js"

const PASSWORD = "correct-horse-battery-staple"

test("a password user connects Google, then signs in with it as the same user", async ({
  app,
  page,
  googleUser,
}) => {
  const user = googleUser("connect")
  await app.seedPasswordUser(user.email, PASSWORD)
  const [native] = (await app.facts(user.email)).users

  await app.signInWithPassword(page, user.email, PASSWORD)
  await expect(app.profileHeading(page, user.email)).toBeVisible()

  await app.startGoogleConnect(page)
  await chooseGoogleAccount(page, user)
  await expect(app.googleAccount(page, user.email)).toBeVisible()
  await expect(app.profileHeading(page, user.email)).toBeVisible()
  const connected = await app.facts(user.email)
  expect(connected).toEqual({
    users: [{ id: native.id, has_password: true }],
    google_accounts: [
      {
        user_id: native.id,
        provider_user_id: expect.any(String),
        provider_email: user.email,
      },
    ],
  })

  await app.signOut(page)
  await app.startGoogleSignIn(page)
  await chooseGoogleAccount(page, user)
  await expect(app.profileHeading(page, user.email)).toBeVisible()
  expect(await app.facts(user.email)).toEqual(connected)
})

test("disconnecting Google keeps the user and password sign-in, and Google can be reconnected", async ({
  app,
  page,
  googleUser,
}) => {
  const user = googleUser("disconnect")
  await app.seedPasswordUser(user.email, PASSWORD)
  const [native] = (await app.facts(user.email)).users

  await app.signInWithPassword(page, user.email, PASSWORD)
  await app.startGoogleConnect(page)
  await chooseGoogleAccount(page, user)
  await expect(app.googleAccount(page, user.email)).toBeVisible()
  const { provider_user_id } = (await app.facts(user.email)).google_accounts[0]

  await app.disconnectGoogle(page, user.email)
  await expect(app.googleAccount(page, user.email)).toHaveCount(0)
  await expect(app.profileHeading(page, user.email)).toBeVisible()
  expect(await app.facts(user.email)).toEqual({
    users: [{ id: native.id, has_password: true }],
    google_accounts: [],
  })

  await app.signOut(page)
  await app.signInWithPassword(page, user.email, PASSWORD)
  await expect(app.profileHeading(page, user.email)).toBeVisible()

  await app.startGoogleConnect(page)
  await chooseGoogleAccount(page, user)
  await expect(app.googleAccount(page, user.email)).toBeVisible()
  expect(await app.facts(user.email)).toEqual({
    users: [{ id: native.id, has_password: true }],
    google_accounts: [
      { user_id: native.id, provider_user_id, provider_email: user.email },
    ],
  })
})

test("Google cannot be disconnected when it is the only way to sign in", async ({
  app,
  page,
  googleUser,
}) => {
  const user = googleUser("last-method")

  await app.startGoogleSignIn(page)
  await chooseGoogleAccount(page, user)
  await expect(app.profileHeading(page, user.email)).toBeVisible()
  const before = await app.facts(user.email)

  await app.disconnectGoogle(page, user.email)
  await expect(
    page.getByText(
      "Cannot disconnect google because it is your only login method.",
    ),
  ).toBeVisible()

  // The refusal leaves the user signed in with the identity connected.
  await app.gotoProfile(page)
  await expect(app.profileHeading(page, user.email)).toBeVisible()
  await expect(app.googleAccount(page, user.email)).toBeVisible()
  expect(await app.facts(user.email)).toEqual(before)
})
