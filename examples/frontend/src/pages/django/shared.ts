import { usePage } from "@inertiajs/react"

// Props every Django page receives from core.inertia.share.
export interface DjangoShared {
  csrf_token: string
  user: { username: string } | null
  urls: {
    home: string
    profile: string
    password_login: string
    logout: string
    google_login: string
    google_link: string
  }
  [key: string]: unknown
}

export function useDjango() {
  return usePage<DjangoShared>().props
}
