import { Link } from "@inertiajs/react"

import { Actions, Field, Grid, Hero, PostForm, Section } from "../../components/ui"
import { SitePage } from "../../layouts"
import { type TwoFactorProps, useCsrfToken } from "./shared"

interface Props extends TwoFactorProps {
  has_password: boolean
  urls: { submit: string; cancel: string }
}

export default function ConfirmIdentity({ site, error, has_password, urls }: Props) {
  const csrfToken = useCsrfToken()
  return (
    <SitePage site={site} title="Confirm it is you">
      <Hero eyebrow="Settings" title="Confirm it is you" notice={error}>
        Changing two-factor authentication needs a recent sign-in.
      </Hero>
      <Grid single>
        <Section>
          <PostForm action={urls.submit} csrfToken={csrfToken} className="stack">
            {has_password && (
              <>
                <Field
                  label="Password"
                  name="password"
                  type="password"
                  autoComplete="current-password"
                />
                <p>Or</p>
              </>
            )}
            <Field
              label="Code from your authenticator app"
              name="code"
              inputMode="numeric"
              autoComplete="one-time-code"
            />
            <Actions>
              <button className="primary" type="submit">
                Confirm
              </button>
            </Actions>
          </PostForm>
          <p>
            No password or authenticator yet? Sign out and sign in again with a
            provider.
          </p>
          <p>
            <Link href={urls.cancel}>Cancel</Link>
          </p>
        </Section>
      </Grid>
    </SitePage>
  )
}
