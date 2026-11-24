import { Link } from "@inertiajs/react"

import { Actions, Grid, Hero, PostForm, Section } from "../../components/ui"
import { DjangoPage } from "../../layouts"
import { useDjango } from "./shared"

export default function Home() {
  const { csrf_token, user, urls } = useDjango()
  return (
    <DjangoPage>
      <Hero eyebrow="Django Demo" title="Sign in with Google next to passwords">
        Cross Auth adds Google sign-in to Django's own authentication: the
        password login, sessions and logout are Django's, and Google accounts
        are stored next to your users.
      </Hero>

      <Grid single>
        <Section title="Session">
          {user ? (
            <>
              <p>
                Signed in as <strong>{user.username}</strong>.
              </p>
              <Actions>
                <Link className="button primary" href={urls.profile}>
                  Your profile
                </Link>
                <PostForm action={urls.logout} csrfToken={csrf_token}>
                  <button type="submit">Sign out</button>
                </PostForm>
              </Actions>
            </>
          ) : (
            <>
              <p>Sign in with Google or with a Django password.</p>
              <Actions>
                <PostForm
                  action={urls.google_login}
                  csrfToken={csrf_token}
                  next={urls.profile}
                >
                  <button className="primary" type="submit">
                    Sign in with Google
                  </button>
                </PostForm>
                <Link className="button" href={urls.password_login}>
                  Sign in with a password
                </Link>
              </Actions>
            </>
          )}
        </Section>
      </Grid>
    </DjangoPage>
  )
}
