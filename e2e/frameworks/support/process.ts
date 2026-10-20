import { type ChildProcess, execFile, spawn } from "node:child_process"
import { once } from "node:events"
import { closeSync, openSync, readFileSync } from "node:fs"
import { promisify } from "node:util"

const execFileAsync = promisify(execFile)

export interface Command {
  args: string[]
  cwd: string
  env: Record<string, string>
}

export interface RunningServer {
  stop(): Promise<void>
}

// Runs a one-off command (migrations, seeding, state queries) and returns stdout.
export async function run({ args, cwd, env }: Command): Promise<string> {
  const [file, ...rest] = args
  try {
    const { stdout } = await execFileAsync(file, rest, {
      cwd,
      env: { ...process.env, ...env },
      timeout: 60_000,
    })
    return stdout
  } catch (error) {
    const { stderr = "" } = error as { stderr?: string }
    throw new Error(`${args.join(" ")} failed:\n${stderr}`, { cause: error })
  }
}

async function responds(url: string): Promise<boolean> {
  try {
    await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(1_000) })
    return true
  } catch {
    return false
  }
}

function tail(logFile: string): string {
  return readFileSync(logFile, "utf8").split("\n").slice(-40).join("\n")
}

// Starts a server in its own process group, writing its output to logFile,
// and resolves once readyUrl answers. Refuses to start when something else
// already answers there, so a test never talks to a server it doesn't own.
export async function startServer(
  command: Command,
  {
    readyUrl,
    logFile,
    timeoutMs = 60_000,
  }: { readyUrl: string; logFile: string; timeoutMs?: number },
): Promise<RunningServer> {
  if (await responds(readyUrl)) {
    throw new Error(
      `${readyUrl} is already in use by a server this run did not start`,
    )
  }

  const log = openSync(logFile, "a")
  const [file, ...args] = command.args
  let child: ChildProcess
  try {
    child = spawn(file, args, {
      cwd: command.cwd,
      env: { ...process.env, ...command.env },
      detached: true,
      stdio: ["ignore", log, log],
    })
  } finally {
    // The child owns its copies of the log descriptor.
    closeSync(log)
  }
  const exited = once(child, "exit")

  const stop = async () => {
    if (child.exitCode !== null || child.signalCode !== null) return
    // uv runs Python as a child, so signal the whole group.
    process.kill(-child.pid!, "SIGTERM")
    const timer = setTimeout(() => process.kill(-child.pid!, "SIGKILL"), 5_000)
    await exited
    clearTimeout(timer)
  }

  const deadline = Date.now() + timeoutMs
  while (!(await responds(readyUrl))) {
    if (child.exitCode !== null) {
      throw new Error(
        `${command.args.join(" ")} exited early:\n${tail(logFile)}`,
      )
    }
    if (Date.now() > deadline) {
      await stop()
      throw new Error(
        `${readyUrl} was not ready after ${timeoutMs} ms:\n${tail(logFile)}`,
      )
    }
    await new Promise((resolve) => setTimeout(resolve, 100))
  }
  return { stop }
}
