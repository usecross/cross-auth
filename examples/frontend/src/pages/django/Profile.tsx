import { Actions, Grid, Hero, Pill, PostForm, Section } from "../../components/ui"
import { DjangoPage } from "../../layouts"
import { useDjango } from "./shared"

interface Props {
  social_accounts: {
    id: number
    provider: string
    provider_email: string
    disconnect_url: string
  }[]
}

export default function Profile({ social_accounts }: Props) {
  const { csrf_token, user, urls } = useDjango()
  return (
    <DjangoPage title="Profile">
      <Hero eyebrow="Signed In" title={user?.username ?? ""}>
        This page uses Django's <code>login_required</code>; the session is
        Django's own, whether you signed in with a password or with Google.
      </Hero>

      <Grid single>
        <Section title="Connected accounts">
          <ul>
            {social_accounts.length > 0 ? (
              social_accounts.map((account) => (
                <li key={account.id}>
                  {account.provider}: {account.provider_email}{" "}
                  <PostForm
                    action={account.disconnect_url}
                    csrfToken={csrf_token}
                    next={urls.profile}
                    className="inline"
                  >
                    <button type="submit">Disconnect</button>
                  </PostForm>
                </li>
              ))
            ) : (
              <li>
                <Pill>None yet.</Pill>
              </li>
            )}
          </ul>
          <Actions>
            <PostForm
              action={urls.google_link}
              csrfToken={csrf_token}
              next={urls.profile}
            >
              <button type="submit">Connect Google</button>
            </PostForm>
            <PostForm action={urls.logout} csrfToken={csrf_token}>
              <button type="submit">Sign out</button>
            </PostForm>
          </Actions>
        </Section>
      </Grid>
    </DjangoPage>
  )
}
