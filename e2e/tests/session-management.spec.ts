import { expect, test } from "./helpers/fixtures.js"

test("session dashboard lists and revokes first-party bearer sessions", async ({
  page, backend, playwright,
}) => {
  await page.goto(`${backend}/`)

  await page.getByLabel("Email").fill("demo@example.com")
  await page.getByLabel("Password").fill("password123")
  await page.getByRole("button", { name: "Sign in with password" }).click()

  await expect(page).toHaveURL(`${backend}/profile`)

  const tokenResponse = await page.request.post(
    `${backend}/auth/token`,
    {
      form: {
        grant_type: "password",
        client_id: "session-management-e2e",
        username: "demo@example.com",
        password: "password123",
      },
    },
  )
  expect(tokenResponse.ok()).toBeTruthy()
  const tokenBody = await tokenResponse.json()
  expect(tokenBody.access_token).toBeTruthy()

  // No browser cookie: otherwise cookie precedence could hide a dead bearer.
  const bearer = await playwright.request.newContext()
  const bearerMe = await bearer.get(`${backend}/api/me`, {
    headers: { Authorization: `Bearer ${tokenBody.access_token}` },
  })
  expect(bearerMe.ok()).toBeTruthy()
  expect(await bearerMe.json()).toMatchObject({
    email: "demo@example.com",
  })

  await page
    .locator(".header-nav")
    .getByRole("link", { name: "Sessions", exact: true })
    .click()
  await expect(page).toHaveURL(`${backend}/sessions`)
  await expect(
    page.getByRole("heading", { name: "Active sessions for demo@example.com" }),
  ).toBeVisible()
  await expect(page.getByTestId("sessions-table")).toBeVisible()
  await expect(page.getByText("Browser (").first()).toBeVisible()
  await expect(
    page.getByText("Authorized Application (session-management-e2e)"),
  ).toBeVisible()

  const apiSessions = await page.request.get(
    `${backend}/api/sessions`,
  )
  expect(apiSessions.ok()).toBeTruthy()
  const sessionsBody = await apiSessions.json()
  expect(sessionsBody.sessions).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        access_label: "Authorized Application (session-management-e2e)",
        status: "active",
      }),
      expect.objectContaining({
        current: true,
        status: "active",
      }),
    ]),
  )

  const bearerRow = page.locator("tr", {
    hasText: "Authorized Application (session-management-e2e)",
  })
  await bearerRow.getByRole("button", { name: "Revoke" }).click()

  await expect(page).toHaveURL(`${backend}/sessions`)
  await expect(bearerRow.getByText("revoked")).toBeVisible()
  await expect(bearerRow.getByText("retained")).toBeVisible()
  const rejected = await bearer.get(`${backend}/api/me`, {
    headers: { Authorization: `Bearer ${tokenBody.access_token}` },
  })
  expect(rejected.status()).toBe(401)
  await bearer.dispose()
})
