import type { InputHTMLAttributes, ReactNode } from "react"

export function Hero({
  eyebrow,
  title,
  children,
  notice,
}: {
  eyebrow: string
  title: ReactNode
  children?: ReactNode
  notice?: string | null
}) {
  return (
    <div className="hero">
      <div className="eyebrow">{eyebrow}</div>
      <h1>{title}</h1>
      {children && <p className="lead">{children}</p>}
      {notice && (
        <div className="notice" role="alert">
          {notice}
        </div>
      )}
    </div>
  )
}

export function Grid({
  single = false,
  children,
}: {
  single?: boolean
  children: ReactNode
}) {
  return <div className={single ? "grid cols-1" : "grid"}>{children}</div>
}

export function Section({
  title,
  full = false,
  children,
}: {
  title?: string
  full?: boolean
  children: ReactNode
}) {
  return (
    <div className={full ? "full stack" : "stack"}>
      {title && <h2>{title}</h2>}
      {children}
    </div>
  )
}

export function Actions({ children }: { children: ReactNode }) {
  return <div className="actions">{children}</div>
}

export function Pill({
  tone,
  children,
}: {
  tone?: "ok" | "warn"
  children: ReactNode
}) {
  return <span className={tone ? `pill ${tone}` : "pill"}>{children}</span>
}

export function Field({
  label,
  ...input
}: { label: string } & InputHTMLAttributes<HTMLInputElement>) {
  return (
    <label className="field">
      <span className="label">{label}</span>
      <input {...input} />
    </label>
  )
}

// A plain browser form post: the backends answer with redirects, some of them
// to an OAuth provider, which an Inertia XHR visit can't follow. Django pages
// pass their CSRF token; FastAPI's form routes don't use one.
export function PostForm({
  action,
  csrfToken,
  next,
  className,
  children,
}: {
  action: string
  csrfToken?: string
  next?: string
  className?: string
  children: ReactNode
}) {
  return (
    <form action={action} method="post" className={className}>
      {csrfToken && (
        <input type="hidden" name="csrfmiddlewaretoken" value={csrfToken} />
      )}
      {next && <input type="hidden" name="next" value={next} />}
      {children}
    </form>
  )
}

export interface HookEvent {
  time: string
  name: string
  [field: string]: string
}

export function HookEvents({ events }: { events: HookEvent[] }) {
  if (events.length === 0) return <Pill>no hook events yet</Pill>
  return (
    <ul>
      {events.map((event, index) => (
        <li key={index}>
          <code>{event.time}</code> <strong>{event.name}</strong>
          {Object.entries(event)
            .filter(([key, value]) => key !== "time" && key !== "name" && value)
            .map(([key, value]) => (
              <span key={key}>
                {" "}
                · {key}=<code>{value}</code>
              </span>
            ))}
        </li>
      ))}
    </ul>
  )
}
