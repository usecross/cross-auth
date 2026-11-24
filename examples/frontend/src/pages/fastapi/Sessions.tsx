import { Link } from "@inertiajs/react"

import { Actions, Grid, Hero, Pill, PostForm, Section } from "../../components/ui"
import { FastAPIPage } from "../../layouts"

interface SessionRow {
  id: number
  status: "active" | "expired" | "revoked"
  access_label: string
  created_at: string
  expires_at: string
  last_active_at: string | null
  client_id: string | null
  user_agent: string | null
  login_method: string | null
  current: boolean
}

interface Props {
  user: { email: string }
  current_status: string | null
  sessions: SessionRow[]
  next_query: string | null
}

// "2026-11-22T10:15:00+00:00" -> "11-22 10:15", as the Jinja page showed it.
function shortTime(iso: string) {
  return iso.slice(5, 16).replace("T", " ")
}

const FILTERS: { label: string; status: string | null }[] = [
  { label: "All", status: null },
  { label: "Active", status: "active" },
  { label: "Expired", status: "expired" },
  { label: "Revoked", status: "revoked" },
]

export default function Sessions({
  user,
  current_status,
  sessions,
  next_query,
}: Props) {
  return (
    <FastAPIPage title="Sessions">
      <Hero
        eyebrow="Session Dashboard"
        title={`Active sessions for ${user.email}`}
      >
        Cookie and first-party bearer sign-ins are stored in the same durable
        session store. Revocation takes effect immediately for both transports.
      </Hero>

      <Grid single>
        <Section>
          <div className="toolbar">
            <nav className="tabs" aria-label="Session filters">
              {FILTERS.map((filter) => (
                <Link
                  key={filter.label}
                  href={
                    filter.status
                      ? `/sessions?status=${filter.status}`
                      : "/sessions"
                  }
                  aria-current={
                    current_status === filter.status ? "page" : undefined
                  }
                >
                  {filter.label}
                </Link>
              ))}
            </nav>
            <Actions>
              <PostForm action="/sessions/revoke-other">
                <button type="submit">Revoke other sessions</button>
              </PostForm>
              <PostForm action="/sessions/revoke-all">
                <button type="submit">Log out everywhere</button>
              </PostForm>
            </Actions>
          </div>

          {sessions.length > 0 ? (
            <div className="table-wrap">
              <table data-testid="sessions-table">
                <thead>
                  <tr>
                    <th>Access</th>
                    <th>Status</th>
                    <th>Created</th>
                    <th>Last active</th>
                    <th>Expires</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {sessions.map((session) => (
                    <tr
                      key={session.id}
                      data-session-id={session.id}
                      data-current={session.current ? "true" : "false"}
                    >
                      <td>
                        <div className="cell-main">
                          <strong>{session.access_label}</strong>
                          {session.current && <Pill tone="ok">current</Pill>}
                          {session.login_method && (
                            <span className="muted-small">
                              via {session.login_method}
                            </span>
                          )}
                          {session.user_agent && (
                            <span className="muted-small">
                              {session.user_agent}
                            </span>
                          )}
                          {session.client_id && (
                            <span className="muted-small">
                              client_id={session.client_id}
                            </span>
                          )}
                        </div>
                      </td>
                      <td>
                        {session.status === "active" ? (
                          <Pill tone="ok">active</Pill>
                        ) : session.status === "revoked" ? (
                          <Pill tone="warn">revoked</Pill>
                        ) : (
                          <Pill>expired</Pill>
                        )}
                      </td>
                      <td>
                        <code>{shortTime(session.created_at)}</code>
                      </td>
                      <td>
                        {session.last_active_at ? (
                          <code>{shortTime(session.last_active_at)}</code>
                        ) : (
                          <Pill>unknown</Pill>
                        )}
                      </td>
                      <td>
                        <code>{shortTime(session.expires_at)}</code>
                      </td>
                      <td>
                        {session.status === "active" && !session.current ? (
                          <PostForm action={`/sessions/${session.id}/revoke`}>
                            <button type="submit">Revoke</button>
                          </PostForm>
                        ) : session.current ? (
                          <Pill>current</Pill>
                        ) : (
                          <Pill>retained</Pill>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Pill>no sessions in this filter</Pill>
          )}
          {next_query && (
            <div className="toolbar">
              <Link
                href={`/sessions?${next_query}`}
                data-testid="sessions-next"
              >
                Next page →
              </Link>
            </div>
          )}
        </Section>
      </Grid>
    </FastAPIPage>
  )
}
