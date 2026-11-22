import { execFileSync } from "node:child_process"
import { resolve } from "node:path"

// Both example backends render their pages from the shared frontend in
// examples/frontend; build it once so they serve the production bundle.
export default function globalSetup() {
  execFileSync("bun", ["run", "build"], {
    cwd: resolve(import.meta.dirname, "../examples/frontend"),
    stdio: "inherit",
  })
}
