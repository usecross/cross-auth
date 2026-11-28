import { usePage } from "@inertiajs/react"

import type { Site } from "../../layouts"

// Props every two-factor page gets from either backend.
export interface TwoFactorProps {
  site: Site
  error?: string | null
}

// Django shares its CSRF token with every page; FastAPI's forms don't use one.
export function useCsrfToken(): string | undefined {
  const token = usePage<{ csrf_token?: string }>().props.csrf_token
  return typeof token === "string" ? token : undefined
}
