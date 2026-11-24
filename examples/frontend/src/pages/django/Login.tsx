import { Actions, Field, Grid, Hero, PostForm, Section } from "../../components/ui"
import { DjangoPage } from "../../layouts"
import { useDjango } from "./shared"

interface Props {
  next: string
  username: string
  form_errors: string[]
}

export default function Login({ next, username, form_errors }: Props) {
  const { csrf_token, urls } = useDjango()
  return (
    <DjangoPage title="Sign in">
      <Hero
        eyebrow="Django Login"
        title="Sign in with a password"
        notice={form_errors.join(" ") || null}
      >
        Django's <code>LoginView</code> checks the password; this page only
        renders its form.
      </Hero>

      <Grid single>
        <Section>
          <PostForm
            action={urls.password_login}
            csrfToken={csrf_token}
            next={next}
            className="stack"
          >
            <Field
              label="Username"
              name="username"
              defaultValue={username}
              autoComplete="username"
              autoFocus
              required
            />
            <Field
              label="Password"
              type="password"
              name="password"
              autoComplete="current-password"
              required
            />
            <Actions>
              <button className="primary" type="submit">
                Sign in
              </button>
            </Actions>
          </PostForm>
        </Section>
      </Grid>
    </DjangoPage>
  )
}
