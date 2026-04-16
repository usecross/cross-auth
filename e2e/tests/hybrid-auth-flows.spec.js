import crypto from "node:crypto"
import { expect, test } from "@playwright/test"

const BACKEND_BASE_URL = "http://127.0.0.1:8000"
const SPA_BASE_URL = "http://127.0.0.1:5173"
const LINK_CALLBACK_URL = `${SPA_BASE_URL}/link-callback`
const SPA_CLIENT_ID = "spa-example"

function base64Url(buffer) {
  return buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "")
}

function generatePkcePair() {
  const codeVerifier = base64Url(crypto.randomBytes(32))
  const codeChallenge = base64Url(
    crypto.createHash("sha256").update(codeVerifier).digest(),
  )

  return { codeVerifier, codeChallenge }
}

async function completeGitHubMockSignIn(page, email, expectedUrlPattern = null) {
  await expect(page).toHaveURL(/github-oauth-mock.*\/login\/oauth\/authorize/)
  await page.getByLabel("Email address").fill(email)

  if (expectedUrlPattern) {
    await Promise.all([
      page.waitForURL(expectedUrlPattern, { timeout: 15_000 }),
      page.getByRole("button", { name: "Sign in" }).click(),
    ])
    return
  }

  await page.getByRole("button", { name: "Sign in" }).click()
}

async function getBackendCookieHeader(page) {
  const cookies = await page.context().cookies(BACKEND_BASE_URL)
  return cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join("; ")
}

async function issuePasswordGrantToken() {
  const response = await fetch(`${BACKEND_BASE_URL}/auth/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "password",
      client_id: SPA_CLIENT_ID,
      username: "demo@example.com",
      password: "password123",
    }),
  })

  expect(response.ok).toBeTruthy()
  const body = await response.json()
  return body.access_token
}

async function initiateGitHubLink({ headers = {} }) {
  const { codeVerifier, codeChallenge } = generatePkcePair()
  const response = await fetch(`${BACKEND_BASE_URL}/auth/github/link`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...headers,
    },
    body: JSON.stringify({
      client_id: SPA_CLIENT_ID,
      redirect_uri: LINK_CALLBACK_URL,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
    }),
  })

  expect(response.ok).toBeTruthy()
  const body = await response.json()

  return {
    authorizationUrl: body.authorization_url,
    codeVerifier,
  }
}

async function finalizeGitHubLink({ headers = {}, linkCode, codeVerifier }) {
  const response = await fetch(`${BACKEND_BASE_URL}/auth/github/finalize-link`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...headers,
    },
    body: JSON.stringify({
      link_code: linkCode,
      code_verifier: codeVerifier,
      allow_login: true,
    }),
  })

  expect(response.ok).toBeTruthy()
  return response.json()
}

test("session account linking succeeds for a session-authenticated user", async ({ page }) => {
  await page.goto(`${BACKEND_BASE_URL}/`)

  await page.getByLabel("Email").fill("demo@example.com")
  await page.getByLabel("Password").fill("password123")
  await page.getByRole("button", { name: "Sign in with password" }).click()

  await expect(page).toHaveURL(/127\.0\.0\.1:8000\/profile/)

  const cookieHeader = await getBackendCookieHeader(page)
  const { authorizationUrl, codeVerifier } = await initiateGitHubLink({
    headers: { Cookie: cookieHeader },
  })

  await page.goto(authorizationUrl)
  await completeGitHubMockSignIn(
    page,
    "demo@example.com",
    /127\.0\.0\.1:5173\/link-callback\?link_code=/,
  )

  await expect(page).toHaveURL(/127\.0\.0\.1:5173\/link-callback\?link_code=/)

  const linkCode = new URL(page.url()).searchParams.get("link_code")
  expect(linkCode).toBeTruthy()

  const finalizeResponse = await finalizeGitHubLink({
    headers: { Cookie: cookieHeader },
    linkCode,
    codeVerifier,
  })
  expect(finalizeResponse).toEqual({ message: "Link finalized" })

  const meResponse = await fetch(`${BACKEND_BASE_URL}/api/me-session`, {
    headers: { Cookie: cookieHeader },
  })
  expect(meResponse.ok).toBeTruthy()
  const me = await meResponse.json()
  expect(me.email).toBe("demo@example.com")
  expect(me.social_accounts.some((account) => account.provider === "github")).toBeTruthy()
})

test("GitHub account linking succeeds for a bearer-authenticated client", async ({ page }) => {
  const accessToken = await issuePasswordGrantToken()
  const { authorizationUrl, codeVerifier } = await initiateGitHubLink({
    headers: { Authorization: `Bearer ${accessToken}` },
  })

  await page.goto(authorizationUrl)
  await completeGitHubMockSignIn(
    page,
    "demo@example.com",
    /127\.0\.0\.1:5173\/link-callback\?link_code=/,
  )

  await expect(page).toHaveURL(/127\.0\.0\.1:5173\/link-callback\?link_code=/)

  const linkCode = new URL(page.url()).searchParams.get("link_code")
  expect(linkCode).toBeTruthy()

  const finalizeResponse = await finalizeGitHubLink({
    headers: { Authorization: `Bearer ${accessToken}` },
    linkCode,
    codeVerifier,
  })
  expect(finalizeResponse).toEqual({ message: "Link finalized" })

  const meResponse = await fetch(`${BACKEND_BASE_URL}/api/me-token`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  })
  expect(meResponse.ok).toBeTruthy()
  const me = await meResponse.json()
  expect(me.email).toBe("demo@example.com")
  expect(me.social_accounts.some((account) => account.provider === "github")).toBeTruthy()
})

test.fixme("session social login succeeds on the FastAPI backend", async ({ page }) => {
  await page.goto("http://127.0.0.1:8000/")

  await page.getByRole("link", { name: "Continue with GitHub" }).click()
  await completeGitHubMockSignIn(
    page,
    "demo@example.com",
    /127\.0\.0\.1:8000\/profile/,
  )

  await expect(page).toHaveURL(/127\.0\.0\.1:8000\/profile/)
  await expect(
    page.getByRole("heading", { name: "demo@example.com" }),
  ).toBeVisible()
  await expect(page.getByText("provider user")).toBeVisible()
})

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
