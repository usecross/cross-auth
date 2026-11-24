import { Link } from "@inertiajs/react"

import {
  Actions,
  Grid,
  Hero,
  type HookEvent,
  HookEvents,
  Section,
} from "../../components/ui"
import { FastAPIPage } from "../../layouts"

export default function Hooks({ hook_events }: { hook_events: HookEvent[] }) {
  return (
    <FastAPIPage title="Hooks">
      <Hero eyebrow="Lifecycle Hooks" title="Hook registrations in this example">
        The FastAPI example uses hooks to trim the local password login email,
        audit successful lifecycle steps, add a response header after session
        creation, block a disallowed provider email domain on OAuth callback,
        and record SPA token exchanges.
      </Hero>

      <Grid>
        <Section title="Registered Hooks">
          <ul>
            <li>
              <code>before:authenticate</code> trims the email; lowercasing and
              +tag stripping run in normalize_email at lookup.
            </li>
            <li>
              <code>after:authenticate</code> records whether password
              authentication succeeded.
            </li>
            <li>
              <code>after:user.create</code> records newly committed local
              users.
            </li>
            <li>
              <code>after:login</code> records session creation and adds{" "}
              <code>X-Cross-Auth-Hook: login</code>.
            </li>
            <li>
              <code>after:logout</code> records the revoked session ID.
            </li>
            <li>
              <code>before:oauth.callback</code> blocks provider emails from a
              disallowed domain (unverified emails are rejected by the
              require_verified_email flag).
            </li>
            <li>
              <code>after:oauth.callback</code> records social session and SPA
              authorization callbacks.
            </li>
            <li>
              <code>after:token.authorization_code</code> records SPA token
              exchanges.
            </li>
          </ul>
        </Section>

        <Section title="Try It">
          <ul>
            <li>
              Submit the local password form from <Link href="/">Home</Link>.
            </li>
            <li>Use Continue with GitHub to run the social session flow.</li>
            <li>Open the SPA demo and complete its auth-code flow.</li>
            <li>Return here to inspect the latest hook events.</li>
          </ul>
          <Actions>
            <Link className="button primary" href="/">
              Home
            </Link>
            <Link className="button" href="/profile">
              Profile
            </Link>
          </Actions>
        </Section>

        <Section title="Recent Events" full>
          <HookEvents events={hook_events} />
        </Section>
      </Grid>
    </FastAPIPage>
  )
}
