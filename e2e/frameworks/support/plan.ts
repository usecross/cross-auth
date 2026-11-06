import type { FullConfig, FullProject } from "@playwright/test"

// FullConfig resolves --workers. TestInfo supplies the scenario's project and
// parallel slot; the provider seed and process startup use this same port.
export function frameworkPort(
  config: FullConfig,
  project: FullProject,
  parallelIndex: number,
): number {
  const projectIndex = config.projects.findIndex(item => item.name === project.name)
  if (projectIndex < 0) throw new Error(`Unknown project: ${project.name}`)
  return 8180 + projectIndex * config.workers + parallelIndex
}
