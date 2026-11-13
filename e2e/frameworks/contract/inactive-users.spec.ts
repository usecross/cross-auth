import { expect, test } from "../support/fixtures.js"
import { chooseGoogleAccount } from "../support/google.js"

test("a suspended user is signed out and refused until restored", async ({
  app,
  page,
  googleUser,
}) => {
  const user = googleUser("suspended")

  await app.startGoogleSignIn(page)
  await chooseGoogleAccount(page, user)
  await expect(app.profileHeading(page, user.email)).toBeVisible()

  // The app's rule refuses the user on the session's next use.
  await app.setActive(user.email, false)
  await app.expectSignedOut(page)

  // And at sign-in, once Google has confirmed the identity.
  await app.startGoogleSignIn(page)
  const callback = page.waitForResponse((response) =>
    response.url().startsWith(app.googleCallbackUrl),
  )
  await chooseGoogleAccount(page, user)
  expect((await callback).status()).toBe(403)
  await app.expectSignedOut(page)

  // Refusing is not revoking: the original session works again.
  await app.setActive(user.email, true)
  await app.gotoProfile(page)
  await expect(app.profileHeading(page, user.email)).toBeVisible()
})
