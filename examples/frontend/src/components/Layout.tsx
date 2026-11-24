import { Head, Link } from "@inertiajs/react"
import type { ReactNode } from "react"

export interface NavItem {
  label: string
  href: string
  // Routes that don't render an Inertia page, such as JSON endpoints, need a
  // full browser navigation instead of an Inertia visit.
  external?: boolean
}

export function Layout({
  title,
  nav,
  footer,
  children,
}: {
  title: string
  nav: NavItem[]
  footer: string
  children: ReactNode
}) {
  return (
    <div className="shell">
      <Head title={title} />
      <header className="header">
        <span className="header-title">cross-auth</span>
        <nav className="header-nav">
          {nav.map((item) =>
            item.external ? (
              <a key={item.href} href={item.href}>
                {item.label}
              </a>
            ) : (
              <Link key={item.href} href={item.href}>
                {item.label}
              </Link>
            ),
          )}
        </nav>
      </header>
      <main>{children}</main>
      <footer className="footer">{footer}</footer>
    </div>
  )
}
