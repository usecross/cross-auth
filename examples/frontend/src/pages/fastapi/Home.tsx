import { Link } from "@inertiajs/react"

import {
  Actions,
  Field,
  Grid,
  Hero,
  type HookEvent,
  HookEvents,
  Pill,
  PostForm,
  Section,
} from "../../components/ui"
import { FastAPIPage } from "../../layouts"

interface Props {
  user: { id: number; email: string } | null
  demo_email: string
  demo_password: string
  error_message: string | null
  github_login_url: string
  github_mock_base_url: string
  google_enabled: boolean
  hook_events: HookEvent[]
  spa_client_id: string
  spa_demo_url: string
}

export default function Home(props: Props) {
  const { user } = props
  return (
    <FastAPIPage>
      <Hero
        eyebrow="FastAPI Hybrid Demo"
        title="Session and auth-server flows on one backend"
        notice={props.error_message}
      >
        This backend demonstrates all three Cross-Auth configurations at once: a
        same-origin session app, a standalone auth-server flow for a separate
        SPA, and the hybrid case where one backend supports both. The local
        login form and GitHub session button end in a browser cookie, while the
        separate SPA uses the generic auth-code + <code>/auth/token</code> flow.
      </Hero>

      <Grid>
        <Section title="Session App">
          {user ? (
            <>
              <p>
                Signed in as <strong>{user.email}</strong>
              </p>
              <p>
                User ID <code>{user.id}</code>
              </p>
              <div className="meta">
                <Pill tone="ok">session active</Pill>
                <Pill>same-origin web app</Pill>
              </div>
              <Actions>
                <Link className="button primary" href="/profile">
                  Profile
                </Link>
                <Link className="button" href="/sessions">
                  Sessions
                </Link>
                <a className="button" href="/api/me">
                  /api/me
                </a>
                <PostForm action="/logout">
                  <button type="submit">Log out</button>
                </PostForm>
              </Actions>
            </>
          ) : (
            <>
              <p>Sign in locally or use GitHub to create a browser session.</p>
              <PostForm action="/login" className="stack">
                <Field
                  label="Email"
                  type="email"
                  name="email"
                  defaultValue={props.demo_email}
                  required
                />
                <Field
                  label="Password"
                  type="password"
                  name="password"
                  defaultValue={props.demo_password}
                  required
                />
                <Actions>
                  <button className="primary" type="submit">
                    Sign in with password
                  </button>
                </Actions>
              </PostForm>
              <Actions>
                <a className="button" href={props.github_login_url}>
                  Continue with GitHub
                </a>
                {props.google_enabled && (
                  <a className="button" href="/auth/google/login?next=/profile">
                    Continue with Google
                  </a>
                )}
              </Actions>
            </>
          )}
        </Section>

        <Section title="Separate SPA Client">
          <p>
            A second app in <code>examples/spa</code> can authenticate against
            this backend as if Cross-Auth were a standalone authentication
            server.
          </p>
          <ul>
            <li>
              Default SPA URL: <code>{props.spa_demo_url}</code>
            </li>
            <li>
              Client ID: <code>{props.spa_client_id}</code>
            </li>
            <li>
              Token endpoint: <code>/auth/token</code>
            </li>
          </ul>
          <Actions>
            <a
              className="button"
              href={props.spa_demo_url}
              target="_blank"
              rel="noreferrer"
            >
              Open SPA demo
            </a>
          </Actions>
          <p>
            The SPA generates PKCE in the browser, redirects to{" "}
            <code>/auth/github/authorize</code>, receives a local auth code at
            its own callback URL, exchanges it at <code>/auth/token</code>, and
            then calls <code>/api/me</code> with a bearer token.
          </p>
        </Section>

        <Section title="Demo Accounts">
          <p>
            Storage runs on the built-in SQLModel adapters over in-memory
            SQLite; the backend seeds one password user at startup.
          </p>
          <ul>
            <li>
              Password login email: <code>{props.demo_email}</code>
            </li>
            <li>
              Password login password: <code>{props.demo_password}</code>
            </li>
            <li>
              Restarting the app resets the user store, social accounts,
              sessions, and tokens.
            </li>
          </ul>
          <p>
            The GitHub button uses{" "}
            <a
              href={props.github_mock_base_url}
              target="_blank"
              rel="noreferrer"
            >
              a public mock GitHub OAuth server
            </a>
            . Enter <code>{props.demo_email}</code> there to link the seeded
            demo user, or any other email to create a new in-memory local user.
          </p>
          <p>
            Emails starting with <code>unverified</code> are treated as
            unverified by the mock and rejected by{" "}
            <code>require_verified_email</code>. Emails at{" "}
            <code>blocked.example</code> are rejected by a{" "}
            <code>before oauth.callback</code> hook; emails at{" "}
            <code>banned.example</code> are rejected by a{" "}
            <code>before user.create</code> hook. Try{" "}
            <code>demo+anything@example.com</code> to see the custom{" "}
            <code>normalize_email</code> resolve it to the seeded demo user.
          </p>
        </Section>

        <Section title="How The Flow Is Chosen">
          <ul>
            <li>
              <code>/auth/github/login</code> starts the session-social flow and
              ends with a browser cookie.
            </li>
            <li>
              <code>/auth/github/authorize</code> starts the generic auth-code
              flow and ends with a local auth code for the SPA.
            </li>
            <li>
              The same backend supports both without changing provider
              configuration.
            </li>
          </ul>
        </Section>

        <Section title="Hook Activity">
          <p>
            This example registers hooks for password authentication, user
            creation, session login/logout, OAuth callbacks, and token exchange.
          </p>
          <HookEvents events={props.hook_events} />
          <Actions>
            <Link className="button" href="/hooks">
              View hook example
            </Link>
          </Actions>
        </Section>

        <Section title="Flow Summary" full>
          <ul>
            <li>
              <strong>Session app:</strong> <code>POST /login</code> calls{" "}
              <code>CrossAuth.authenticate(...)</code> and{" "}
              <code>CrossAuth.login(...)</code>.
            </li>
            <li>
              <strong>Social session login:</strong>{" "}
              <code>/auth/github/login</code> redirects to GitHub, then{" "}
              <code>/auth/github/callback</code> resolves the local user and
              sets the session cookie.
            </li>
            <li>
              <strong>Auth-server login:</strong> the SPA calls{" "}
              <code>/auth/github/authorize</code>, receives a local auth code at
              its own callback URL, then exchanges it at{" "}
              <code>/auth/token</code>.
            </li>
          </ul>
        </Section>
      </Grid>
    </FastAPIPage>
  )
}
