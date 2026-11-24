import { useEffect, useRef, useState } from "react"

import { FastAPIPage } from "../../layouts"
import { LINK_PROVIDER_KEY, LINK_VERIFIER_KEY } from "./Profile"

export default function LinkCallback({ next_url }: { next_url: string }) {
  const [message, setMessage] = useState(
    "Completing the provider callback and linking your account...",
  )
  // The verifier is single-use: finalize once even if effects run twice.
  const started = useRef(false)

  useEffect(() => {
    if (started.current) return
    started.current = true

    async function finalizeLink() {
      const params = new URLSearchParams(window.location.search)
      const linkCode = params.get("link_code")
      const codeVerifier = window.sessionStorage.getItem(LINK_VERIFIER_KEY)
      const provider =
        window.sessionStorage.getItem(LINK_PROVIDER_KEY) || "github"
      window.sessionStorage.removeItem(LINK_VERIFIER_KEY)
      window.sessionStorage.removeItem(LINK_PROVIDER_KEY)

      if (!linkCode || !codeVerifier) {
        setMessage(
          "Missing link code or PKCE verifier. Please restart the link flow.",
        )
        return
      }

      try {
        const response = await fetch(`/auth/${provider}/finalize-link`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            link_code: linkCode,
            code_verifier: codeVerifier,
            allow_login: true,
          }),
        })
        if (!response.ok) {
          const body = await response.text()
          throw new Error(body || "Failed to finalize account link")
        }
        setMessage("Account linked. Redirecting back to your profile...")
        window.setTimeout(() => window.location.replace(next_url), 400)
      } catch (error) {
        setMessage(
          error instanceof Error
            ? error.message
            : "Failed to finalize account link",
        )
      }
    }

    void finalizeLink()
  }, [next_url])

  return (
    <FastAPIPage title="Link Account">
      <div className="hero">
        <div className="eyebrow">Account Linking</div>
        <h1>Finalizing account link</h1>
        <p className="lead" id="link-message">
          {message}
        </p>
      </div>
    </FastAPIPage>
  )
}
