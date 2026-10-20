import { createEmulator } from "emulate"

import { frameworks } from "../frameworks.js"
import { googleSeed, MAX_WORKERS } from "./google.js"

// Starts the Google emulator in the runner process; workers inherit its URL.
export default async function globalSetup(): Promise<() => Promise<void>> {
  const callbackUrls = Object.values(frameworks).flatMap(({ basePort }) =>
    Array.from(
      { length: MAX_WORKERS },
      (_, index) => `http://127.0.0.1:${basePort + index}/auth/google/callback`,
    ),
  )
  const emulator = await createEmulator({
    service: "google",
    port: 0,
    hostname: "127.0.0.1",
    seed: googleSeed(callbackUrls),
  })
  process.env.GOOGLE_EMULATOR_URL = emulator.url
  return () => emulator.close()
}
