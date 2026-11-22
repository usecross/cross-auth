import { Link } from "@inertiajs/react"
import { useState } from "react"

import {
  Actions,
  Grid,
  Hero,
  type HookEvent,
  HookEvents,
  Pill,
  PostForm,
  Section,
} from "../../components/ui"
import { FastAPIPage } from "../../layouts"

interface SocialAccount {
  id: number
  provider: string
  provider_user_id: string
  provider_email: string | null
  provider_email_verified: boolean
  is_login_method: boolean
}

interface Props {
  user: {
    id: number
    email: string
    email_verified: boolean
    social_accounts: SocialAccount[]
  }
  google_enabled: boolean
  hook_events: HookEvent[]
  spa_client_id: string
}

export const LINK_VERIFIER_KEY = "cross_auth_fastapi_link_code_verifier"
export const LINK_PROVIDER_KEY = "cross_auth_fastapi_link_provider"

function generateRandomString() {
  const bytes = new Uint8Array(32)
  window.crypto.getRandomValues(bytes)
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  )
}

async function generateCodeChallenge(verifier: string) {
  const data = new TextEncoder().encode(verifier)
  const digest = await window.crypto.subtle.digest("SHA-256", data)
  const base64 = btoa(String.fromCharCode(...new Uint8Array(digest)))
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

function errorMessage(error: unknown, fallback: string) {
  return error instanceof Error ? error.message : fallback
}

export default function Profile({
  user,
  google_enabled,
  hook_events,
  spa_client_id,
}: Props) {
  const [linkStatus, setLinkStatus] = useState<string | null>(null)
  const [linking, setLinking] = useState<string | null>(null)
  const [disconnectStatus, setDisconnectStatus] = useState<string | null>(null)
  const [disconnecting, setDisconnecting] = useState<number | null>(null)

  // Both buttons wait on one attempt: they share the stored PKCE verifier.
  async function linkAccount(provider: string) {
    try {
      setLinking(provider)
      setLinkStatus("Redirecting to the provider to link your account...")
      const codeVerifier = generateRandomString()
      const codeChallenge = await generateCodeChallenge(codeVerifier)
      window.sessionStorage.setItem(LINK_VERIFIER_KEY, codeVerifier)
      window.sessionStorage.setItem(LINK_PROVIDER_KEY, provider)

      const response = await fetch(`/auth/${provider}/link`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_id: spa_client_id,
          redirect_uri: `${window.location.origin}/link-callback`,
          code_challenge: codeChallenge,
          code_challenge_method: "S256",
        }),
      })
      if (!response.ok) {
        const body = await response.text()
        throw new Error(body || "Failed to initiate account linking")
      }
      const data = (await response.json()) as { authorization_url: string }
      window.location.href = data.authorization_url
    } catch (error) {
      setLinking(null)
      setLinkStatus(errorMessage(error, "Failed to initiate account linking"))
    }
  }

  async function disconnect(account: SocialAccount) {
    setDisconnecting(account.id)
    try {
      // HTML forms can't issue DELETE; fetch carries the session cookie.
      const response = await fetch(
        `/auth/${account.provider}/social-accounts/${account.id}`,
        { method: "DELETE" },
      )
      if (!response.ok) {
        const body = (await response.json().catch(() => ({}))) as {
          error?: string
          error_description?: string
        }
        // Surfaces the "no_alternative_login_method" guard message inline.
        throw new Error(
          body.error_description ||
            body.error ||
            "Failed to disconnect account",
        )
      }
      window.location.reload()
    } catch (error) {
      setDisconnecting(null)
      setDisconnectStatus(errorMessage(error, "Failed to disconnect account"))
    }
  }

  return (
    <FastAPIPage title="Profile">
      <Hero eyebrow="Signed In" title={user.email}>
        This page is protected by the session cookie written either by{" "}
        <code>CrossAuth.login(...)</code> or by the GitHub session-social
        callback flow. The same backend also exposes bearer-token APIs for the
        separate SPA demo.
      </Hero>

      <Grid>
        <Section title="Local User">
          <p>
            <strong>User ID</strong> &nbsp;<code>{user.id}</code>
          </p>
          <p>
            <strong>Email verified</strong> &nbsp;
            {user.email_verified ? (
              <Pill tone="ok">yes</Pill>
            ) : (
              <Pill tone="warn">no</Pill>
            )}
          </p>
          <div className="stack">
            <p>
              <strong>Social accounts</strong>
            </p>
            {user.social_accounts.length > 0 ? (
              <>
                <ul>
                  {user.social_accounts.map((account) => (
                    <li key={account.id} data-social-account-id={account.id}>
                      <code>{account.provider}</code> · provider user{" "}
                      <code>{account.provider_user_id}</code>
                      {account.provider_email && (
                        <> · {account.provider_email}</>
                      )}{" "}
                      {account.provider_email_verified ? (
                        <Pill tone="ok">verified</Pill>
                      ) : (
                        <Pill tone="warn">unverified or unknown</Pill>
                      )}{" "}
                      {account.is_login_method && <Pill>login method</Pill>}{" "}
                      <button
                        type="button"
                        disabled={disconnecting === account.id}
                        onClick={() => void disconnect(account)}
                      >
                        Disconnect
                      </button>
                    </li>
                  ))}
                </ul>
                <p
                  id="disconnect-status"
                  className="notice"
                  hidden={disconnectStatus === null}
                >
                  {disconnectStatus}
                </p>
              </>
            ) : (
              <Pill>none linked</Pill>
            )}
          </div>
          <Actions>
            <Link className="button" href="/">
              Home
            </Link>
            <Link className="button" href="/sessions">
              Manage sessions
            </Link>
            <a className="button" href="/api/me">
              /api/me
            </a>
            <a
              className="button"
              href="http://localhost:5173"
              target="_blank"
              rel="noreferrer"
            >
              Open SPA demo
            </a>
            <button
              type="button"
              disabled={linking !== null}
              onClick={() => void linkAccount("github")}
            >
              Link GitHub account
            </button>
            <a
              className="button"
              href="/auth/github/connect?next=/profile"
              id="connect-github-link"
            >
              Connect GitHub (session)
            </a>
            {google_enabled && (
              <>
                <button
                  type="button"
                  disabled={linking !== null}
                  onClick={() => void linkAccount("google")}
                >
                  Link Google account
                </button>
                <a className="button" href="/auth/google/connect?next=/profile">
                  Connect Google (session)
                </a>
              </>
            )}
            <PostForm action="/logout">
              <button type="submit">Log out</button>
            </PostForm>
          </Actions>
          <p id="link-status" className="notice" hidden={linkStatus === null}>
            {linkStatus}
          </p>
        </Section>

        <Section title="What This Backend Covers">
          <ul>
            <li>
              In-memory user storage implementing the Cross-Auth account
              protocols
            </li>
            <li>
              Session-based password login and logout for a normal FastAPI app
            </li>
            <li>
              Social login to browser session using the mock GitHub OAuth server
            </li>
            <li>
              Generic auth-code + <code>/auth/token</code> flow for a separate
              SPA client
            </li>
            <li>
              Protected page rendering and both session- and bearer-authenticated
              JSON responses
            </li>
          </ul>
        </Section>

        <Section title="Recent Hook Activity" full>
          <HookEvents events={hook_events} />
          <Actions>
            <Link className="button" href="/hooks">
              View hook example
            </Link>
          </Actions>
        </Section>
      </Grid>
    </FastAPIPage>
  )
}
