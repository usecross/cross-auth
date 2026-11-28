import { Actions, Field, Grid, Hero, PostForm, Section } from "../../components/ui"
import { SitePage } from "../../layouts"
import { type TwoFactorProps, useCsrfToken } from "./shared"

interface Props extends TwoFactorProps {
  expired: boolean
  // "totp" and "recovery_code", the ways this sign-in can finish.
  methods: string[]
  next: string
  urls: { verify: string; sign_in: string }
}

// The sign-in step between the first factor and the session. The forms post
// to the library's verify endpoint, which reads the challenge cookie.
export default function Verify({ site, error, expired, methods, next, urls }: Props) {
  const csrfToken = useCsrfToken()
  return (
    <SitePage site={site} title="Two-factor authentication">
      <Hero eyebrow="Sign in" title="Two-factor authentication" notice={error} />
      <Grid single>
        <Section>
          {expired ? (
            <p>
              <a href={urls.sign_in}>Sign in again</a>
            </p>
          ) : (
            <>
              {methods.includes("totp") && (
                <PostForm
                  action={urls.verify}
                  csrfToken={csrfToken}
                  next={next || undefined}
                  className="stack"
                >
                  <Field
                    label="Code from your authenticator app"
                    name="code"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    pattern="[0-9 ]*"
                    required
                    autoFocus
                  />
                  <Actions>
                    <button className="primary" type="submit">
                      Verify
                    </button>
                  </Actions>
                </PostForm>
              )}
              {methods.includes("recovery_code") && (
                <details>
                  <summary>Use a recovery code</summary>
                  <PostForm
                    action={urls.verify}
                    csrfToken={csrfToken}
                    next={next || undefined}
                    className="stack"
                  >
                    <Field
                      label="Recovery code"
                      name="recovery_code"
                      autoComplete="off"
                      autoCapitalize="none"
                      spellCheck={false}
                      required
                    />
                    <Actions>
                      <button type="submit">Verify</button>
                    </Actions>
                  </PostForm>
                </details>
              )}
            </>
          )}
        </Section>
      </Grid>
    </SitePage>
  )
}
