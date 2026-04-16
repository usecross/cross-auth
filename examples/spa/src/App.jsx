import { useEffect, useMemo, useRef, useState } from "react"

const DEFAULT_BACKEND_BASE_URL =
  import.meta.env.VITE_BACKEND_BASE_URL ?? "http://127.0.0.1:8000"
const DEFAULT_CLIENT_ID = import.meta.env.VITE_CLIENT_ID ?? "spa-example"
const DEFAULT_PROVIDER = import.meta.env.VITE_PROVIDER ?? "github"
const DEFAULT_EMAIL = "demo@example.com"
const DEFAULT_PASSWORD = "password123"

const STORAGE_KEYS = {
  backendBaseUrl: "cross_auth_spa_backend_base_url",
  clientId: "cross_auth_spa_client_id",
  accessToken: "cross_auth_spa_access_token",
  codeVerifier: "cross_auth_spa_code_verifier",
  oauthState: "cross_auth_spa_oauth_state",
  linkCodeVerifier: "cross_auth_spa_link_code_verifier",
}

function getInitialValue(key, fallback) {
  return window.localStorage.getItem(key) ?? fallback
}

function generateRandomString() {
  const bytes = new Uint8Array(32)
  window.crypto.getRandomValues(bytes)
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")
}

async function generateCodeChallenge(verifier) {
  const encoder = new TextEncoder()
  const data = encoder.encode(verifier)
  const digest = await window.crypto.subtle.digest("SHA-256", data)
  const base64 = btoa(String.fromCharCode(...new Uint8Array(digest)))
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

export default function App() {
  const [backendBaseUrl, setBackendBaseUrl] = useState(() =>
    getInitialValue(STORAGE_KEYS.backendBaseUrl, DEFAULT_BACKEND_BASE_URL),
  )
  const [clientId, setClientId] = useState(() =>
    getInitialValue(STORAGE_KEYS.clientId, DEFAULT_CLIENT_ID),
  )
  const [email, setEmail] = useState(DEFAULT_EMAIL)
  const [password, setPassword] = useState(DEFAULT_PASSWORD)
  const [accessToken, setAccessToken] = useState(() =>
    window.localStorage.getItem(STORAGE_KEYS.accessToken) ?? "",
  )
  const [status, setStatus] = useState("idle")
  const [error, setError] = useState("")
  const [tokenUser, setTokenUser] = useState(null)
  const hasHandledAuthCallback = useRef(false)
  const hasHandledLinkCallback = useRef(false)

  const callbackUrl = `${window.location.origin}/callback`
  const linkCallbackUrl = `${window.location.origin}/link-callback`
  const isAuthCallbackRoute = window.location.pathname === "/callback"
  const isLinkCallbackRoute = window.location.pathname === "/link-callback"
  const authBaseUrl = useMemo(() => backendBaseUrl.replace(/\/$/, ""), [backendBaseUrl])

  useEffect(() => {
    window.localStorage.setItem(STORAGE_KEYS.backendBaseUrl, backendBaseUrl)
  }, [backendBaseUrl])

  useEffect(() => {
    window.localStorage.setItem(STORAGE_KEYS.clientId, clientId)
  }, [clientId])

  useEffect(() => {
    if (!isAuthCallbackRoute || hasHandledAuthCallback.current) {
      return
    }

    hasHandledAuthCallback.current = true

    const handleCallback = async () => {
      setStatus("authenticating")
      setError("")

      const searchParams = new URLSearchParams(window.location.search)
      const returnedState = searchParams.get("state")
      const storedState = window.sessionStorage.getItem(STORAGE_KEYS.oauthState)

      if (!returnedState || !storedState || returnedState !== storedState) {
        setStatus("error")
        setError("State mismatch. Please restart the login flow.")
        return
      }

      window.sessionStorage.removeItem(STORAGE_KEYS.oauthState)

      const providerError = searchParams.get("error")
      if (providerError) {
        setStatus("error")
        setError(searchParams.get("error_description") ?? providerError)
        return
      }

      const code = searchParams.get("code")
      const codeVerifier = window.sessionStorage.getItem(STORAGE_KEYS.codeVerifier)
      window.sessionStorage.removeItem(STORAGE_KEYS.codeVerifier)

      if (!code || !codeVerifier) {
        setStatus("error")
        setError("Missing authorization code or PKCE verifier.")
        return
      }

      try {
        const response = await fetch(`${authBaseUrl}/auth/token`, {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: new URLSearchParams({
            grant_type: "authorization_code",
            client_id: clientId,
            code,
            redirect_uri: callbackUrl,
            code_verifier: codeVerifier,
          }),
        })

        if (!response.ok) {
          const body = await response.text()
          throw new Error(body || "Failed to exchange authorization code")
        }

        const tokenResponse = await response.json()
        window.localStorage.setItem(
          STORAGE_KEYS.accessToken,
          tokenResponse.access_token,
        )
        setAccessToken(tokenResponse.access_token)
        setStatus("authenticated")
        window.history.replaceState({}, "", "/")
      } catch (callbackError) {
        setStatus("error")
        setError(
          callbackError instanceof Error
            ? callbackError.message
            : "Failed to exchange authorization code",
        )
      }
    }

    void handleCallback()
  }, [authBaseUrl, callbackUrl, clientId, isAuthCallbackRoute])

  useEffect(() => {
    if (!isLinkCallbackRoute || hasHandledLinkCallback.current) {
      return
    }

    hasHandledLinkCallback.current = true

    const handleLinkCallback = async () => {
      setStatus("linking")
      setError("")

      const searchParams = new URLSearchParams(window.location.search)
      const providerError = searchParams.get("error")
      if (providerError) {
        setStatus("error")
        setError(searchParams.get("error_description") ?? providerError)
        return
      }

      const linkCode = searchParams.get("link_code")
      const codeVerifier = window.sessionStorage.getItem(STORAGE_KEYS.linkCodeVerifier)
      window.sessionStorage.removeItem(STORAGE_KEYS.linkCodeVerifier)

      if (!accessToken) {
        setStatus("error")
        setError("No bearer token available to finalize account linking.")
        return
      }

      if (!linkCode || !codeVerifier) {
        setStatus("error")
        setError("Missing link code or PKCE verifier.")
        return
      }

      try {
        const response = await fetch(`${authBaseUrl}/auth/${DEFAULT_PROVIDER}/finalize-link`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${accessToken}`,
          },
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

        window.history.replaceState({}, "", "/")
        await fetchTokenUser(accessToken)
        setStatus("authenticated")
      } catch (linkError) {
        setStatus("error")
        setError(
          linkError instanceof Error
            ? linkError.message
            : "Failed to finalize account link",
        )
      }
    }

    void handleLinkCallback()
  }, [accessToken, authBaseUrl, isLinkCallbackRoute])

  useEffect(() => {
    if (!accessToken || isAuthCallbackRoute || isLinkCallbackRoute) {
      return
    }

    void fetchTokenUser(accessToken)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [accessToken, isAuthCallbackRoute, isLinkCallbackRoute])

  async function fetchTokenUser(token = accessToken) {
    if (!token) {
      setTokenUser(null)
      return
    }

    setStatus("loading-user")
    setError("")

    try {
      const response = await fetch(`${authBaseUrl}/api/me-token`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      })

      if (!response.ok) {
        const body = await response.text()
        throw new Error(body || "Failed to fetch bearer-authenticated user")
      }

      const data = await response.json()
      setTokenUser(data)
      setStatus("authenticated")
    } catch (fetchError) {
      setStatus("error")
      setError(
        fetchError instanceof Error
          ? fetchError.message
          : "Failed to fetch bearer-authenticated user",
      )
    }
  }

  async function beginPasswordLogin() {
    setError("")
    setStatus("authenticating")

    try {
      const response = await fetch(`${authBaseUrl}/auth/token`, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          grant_type: "password",
          client_id: clientId,
          username: email,
          password,
        }),
      })

      if (!response.ok) {
        const body = await response.text()
        throw new Error(body || "Failed to sign in with password")
      }

      const tokenResponse = await response.json()
      window.localStorage.setItem(
        STORAGE_KEYS.accessToken,
        tokenResponse.access_token,
      )
      setAccessToken(tokenResponse.access_token)
      setStatus("authenticated")
    } catch (loginError) {
      setStatus("error")
      setError(
        loginError instanceof Error
          ? loginError.message
          : "Failed to sign in with password",
      )
    }
  }

  async function beginSocialLogin() {
    setError("")
    setStatus("redirecting")

    const codeVerifier = generateRandomString()
    const codeChallenge = await generateCodeChallenge(codeVerifier)
    const state = generateRandomString()

    window.sessionStorage.setItem(STORAGE_KEYS.codeVerifier, codeVerifier)
    window.sessionStorage.setItem(STORAGE_KEYS.oauthState, state)

    const params = new URLSearchParams({
      client_id: clientId,
      redirect_uri: callbackUrl,
      response_type: "code",
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      state,
    })

    window.location.href = `${authBaseUrl}/auth/${DEFAULT_PROVIDER}/authorize?${params.toString()}`
  }

  async function beginSocialLink() {
    if (!accessToken) {
      setStatus("error")
      setError("Sign in first before linking a GitHub account.")
      return
    }

    setError("")
    setStatus("redirecting")

    try {
      const codeVerifier = generateRandomString()
      const codeChallenge = await generateCodeChallenge(codeVerifier)
      window.sessionStorage.setItem(STORAGE_KEYS.linkCodeVerifier, codeVerifier)

      const response = await fetch(`${authBaseUrl}/auth/${DEFAULT_PROVIDER}/link`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${accessToken}`,
        },
        body: JSON.stringify({
          client_id: clientId,
          redirect_uri: linkCallbackUrl,
          code_challenge: codeChallenge,
          code_challenge_method: "S256",
        }),
      })

      if (!response.ok) {
        const body = await response.text()
        throw new Error(body || "Failed to initiate account link")
      }

      const data = await response.json()
      window.location.href = data.authorization_url
    } catch (linkError) {
      setStatus("error")
      setError(
        linkError instanceof Error
          ? linkError.message
          : "Failed to initiate account link",
      )
    }
  }

  function clearToken() {
    window.localStorage.removeItem(STORAGE_KEYS.accessToken)
    setAccessToken("")
    setTokenUser(null)
    setStatus("idle")
    setError("")
  }

  return (
    <div className="shell">
      <header className="hero">
        <div className="eyebrow">Separate SPA Demo</div>
        <h1>Authenticate against Cross-Auth as a separate app</h1>
        <p className="lead">
          This Vite + React app treats the FastAPI demo backend like a standalone
          authentication service. It can log in with either password grant or GitHub,
          receives a bearer token, and can also link a GitHub account to the current
          bearer-authenticated user.
        </p>
      </header>

      <main className="grid">
        <section className="card stack">
          <h2>Connection</h2>
          <label className="field">
            <span>Backend base URL</span>
            <input
              value={backendBaseUrl}
              onChange={(event) => setBackendBaseUrl(event.target.value)}
              placeholder="http://127.0.0.1:8000"
            />
          </label>
          <label className="field">
            <span>Client ID</span>
            <input
              value={clientId}
              onChange={(event) => setClientId(event.target.value)}
              placeholder="spa-example"
            />
          </label>
          <div className="meta">
            <span className="pill">provider: {DEFAULT_PROVIDER}</span>
            <span className="pill">callback: {callbackUrl}</span>
            <span className="pill">link callback: {linkCallbackUrl}</span>
          </div>
          <div className="actions">
            <button className="primary" onClick={beginSocialLogin}>
              Log in with GitHub
            </button>
            <button onClick={beginSocialLink} disabled={!accessToken}>
              Link GitHub account
            </button>
            <a className="button" href={authBaseUrl} target="_blank" rel="noreferrer">
              Open backend demo
            </a>
          </div>
        </section>

        <section className="card stack">
          <h2>Password Login</h2>
          <label className="field">
            <span>Email</span>
            <input
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              placeholder="demo@example.com"
              type="email"
            />
          </label>
          <label className="field">
            <span>Password</span>
            <input
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="password123"
              type="password"
            />
          </label>
          <div className="actions">
            <button onClick={beginPasswordLogin}>Log in with password</button>
          </div>
        </section>

        <section className="card stack">
          <h2>Status</h2>
          <div className="meta">
            <span className={`pill ${accessToken ? "ok" : ""}`}>
              {accessToken ? "token present" : "no token"}
            </span>
            <span className="pill">state: {status}</span>
          </div>
          {error ? <div className="notice">{error}</div> : null}
          {!error && isAuthCallbackRoute ? (
            <p>Handling the provider callback and exchanging the local auth code...</p>
          ) : null}
          {!error && isLinkCallbackRoute ? (
            <p>Handling the provider callback and finalizing the account link...</p>
          ) : null}
          <div className="actions">
            <button onClick={() => void fetchTokenUser()} disabled={!accessToken}>
              Call /api/me-token
            </button>
            <button onClick={clearToken} disabled={!accessToken}>
              Clear token
            </button>
          </div>
        </section>

        <section className="card stack full">
          <h2>Bearer Token</h2>
          {accessToken ? <pre>{accessToken}</pre> : <p>No token stored yet.</p>}
        </section>

        <section className="card stack full">
          <h2>Bearer-Protected API Result</h2>
          {tokenUser ? <pre>{JSON.stringify(tokenUser, null, 2)}</pre> : <p>No API response yet.</p>}
        </section>

        <section className="card stack full">
          <h2>Flow</h2>
          <ol>
            <li>Authenticate with password grant or with GitHub auth-code flow.</li>
            <li>Store the returned bearer token locally.</li>
            <li>Call <code>/api/me-token</code> with <code>Authorization: Bearer ...</code>.</li>
            <li>Optionally click <code>Link GitHub account</code> to start linking.</li>
            <li>After the provider callback, POST the link code and verifier to <code>/auth/github/finalize-link</code>.</li>
          </ol>
        </section>
      </main>
    </div>
  )
}
