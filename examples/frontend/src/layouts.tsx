import type { ReactNode } from "react"

import { Layout } from "./components/Layout"

export function FastAPIPage({
  title,
  children,
}: {
  title?: string
  children: ReactNode
}) {
  const site = "Cross-Auth FastAPI Hybrid Example"
  return (
    <Layout
      title={title ? `${title} · ${site}` : site}
      nav={[
        { label: "Home", href: "/" },
        { label: "Profile", href: "/profile" },
        { label: "Sessions", href: "/sessions" },
        { label: "Hooks", href: "/hooks" },
        { label: "/me", href: "/api/me", external: true },
      ]}
      footer="cross-auth fastapi hybrid example"
    >
      {children}
    </Layout>
  )
}

export function DjangoPage({
  title,
  children,
}: {
  title?: string
  children: ReactNode
}) {
  const site = "Cross Auth Django example"
  return (
    <Layout
      title={title ? `${title} · ${site}` : site}
      nav={[
        { label: "Home", href: "/" },
        { label: "Profile", href: "/profile/" },
        { label: "Admin", href: "/admin/", external: true },
      ]}
      footer="cross-auth django example"
    >
      {children}
    </Layout>
  )
}
