import { Link } from "@inertiajs/react"

import { Actions, Grid, Hero, PostForm, Section } from "../../components/ui"
import { SitePage } from "../../layouts"
import { type TwoFactorProps, useCsrfToken } from "./shared"

interface Props extends TwoFactorProps {
  mfa: {
    enabled: boolean
    recovery_codes_remaining: number
    factors: { id: string; name: string; added: string; remove_url: string }[]
  }
  urls: { start: string; recovery_codes: string; back: string }
}

export default function Settings({ site, error, mfa, urls }: Props) {
  const csrfToken = useCsrfToken()
  return (
    <SitePage site={site} title="Two-factor authentication">
      <Hero eyebrow="Settings" title="Two-factor authentication" notice={error} />
      <Grid single>
        {mfa.enabled ? (
          <>
            <Section>
              <p data-testid="mfa-status">Two-factor authentication is on.</p>
              <p data-testid="recovery-codes-remaining">
                {mfa.recovery_codes_remaining} recovery codes left.
              </p>
            </Section>
            <Section title="Authenticators">
              <ul>
                {mfa.factors.map((factor) => (
                  <li key={factor.id} data-testid="mfa-factor">
                    {factor.name}, added {factor.added}{" "}
                    <PostForm
                      action={factor.remove_url}
                      csrfToken={csrfToken}
                      className="inline"
                    >
                      <button type="submit">Remove</button>
                    </PostForm>
                  </li>
                ))}
              </ul>
            </Section>
            <Section title="Recovery codes">
              <p>
                Each code signs you in once if you lose your phone. New codes
                replace the old ones.
              </p>
              <Actions>
                <PostForm action={urls.recovery_codes} csrfToken={csrfToken}>
                  <button type="submit">Regenerate recovery codes</button>
                </PostForm>
              </Actions>
            </Section>
          </>
        ) : (
          <Section>
            <p data-testid="mfa-status">Two-factor authentication is off.</p>
            <p>Ask for a code from an authenticator app each time you sign in.</p>
            <Actions>
              <PostForm action={urls.start} csrfToken={csrfToken}>
                <button className="primary" type="submit">
                  Set up an authenticator app
                </button>
              </PostForm>
            </Actions>
          </Section>
        )}
        <Section>
          <p>
            <Link href={urls.back}>Back to profile</Link>
          </p>
        </Section>
      </Grid>
    </SitePage>
  )
}
