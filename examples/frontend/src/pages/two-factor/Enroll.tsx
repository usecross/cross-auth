import { Link } from "@inertiajs/react"

import { Actions, Field, Grid, Hero, PostForm, Section } from "../../components/ui"
import { SitePage } from "../../layouts"
import { type TwoFactorProps, useCsrfToken } from "./shared"

interface Props extends TwoFactorProps {
  enrollment_id: string
  secret: string
  otpauth_uri: string
  // Rendered by the backend: the URI holds the secret, so no QR service.
  qr_svg: string
  urls: { confirm: string; cancel: string }
}

export default function Enroll(props: Props) {
  const csrfToken = useCsrfToken()
  return (
    <SitePage site={props.site} title="Set up an authenticator app">
      <Hero
        eyebrow="Settings"
        title="Set up an authenticator app"
        notice={props.error}
      />
      <Grid single>
        <Section>
          <p>Scan this code with your authenticator app.</p>
          <figure
            data-testid="totp-qr"
            className="qr"
            dangerouslySetInnerHTML={{ __html: props.qr_svg }}
          />
          <p>
            Or enter this key by hand:{" "}
            <code data-testid="totp-secret">{props.secret}</code>
          </p>
          <PostForm action={props.urls.confirm} csrfToken={csrfToken} className="stack">
            <input type="hidden" name="enrollment_id" value={props.enrollment_id} />
            <input type="hidden" name="secret" value={props.secret} />
            <input type="hidden" name="otpauth_uri" value={props.otpauth_uri} />
            <Field
              label="Code from your authenticator app"
              name="code"
              inputMode="numeric"
              autoComplete="one-time-code"
              required
              autoFocus
            />
            <Actions>
              <button className="primary" type="submit">
                Turn on
              </button>
            </Actions>
          </PostForm>
          <p>
            <Link href={props.urls.cancel}>Cancel</Link>
          </p>
        </Section>
      </Grid>
    </SitePage>
  )
}
