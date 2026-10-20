import { django } from "./django/app.js"
import { fastapi } from "./fastapi/app.js"
import type { Framework } from "./support/app.js"

// Every framework here runs all of frameworks/contract. Adding one means a
// driver (see support/app.ts), its server bootstrap, and an entry below.
export const frameworks = { django, fastapi } satisfies Record<
  string,
  Framework
>

export type FrameworkName = keyof typeof frameworks
