/**
 * Named persistent workspace stubs.
 *
 * These functions will wrap the Vercel Sandbox named-sandbox APIs in Phase 2.
 * In Phase 0 every function is a safe no-op / always-returns-null stub so
 * that SandboxManager can import them without affecting the task pipeline.
 *
 * IMPORTANT: Do NOT add dynamic values to any log statements here.
 * Static strings only per project security policy.
 */

import { createHash } from 'node:crypto'

// Import the Drizzle table for type reference.
// DO NOT query it yet — real reads/writes land in Phase 2+.
import { sandboxWorkspaces } from '@/lib/db/schema'

// Re-export for consumers that need the table type.
export { sandboxWorkspaces }

/** Maximum byte-length of a workspace name sent to Vercel Sandbox SDK. */
const MAX_WORKSPACE_NAME_LENGTH = 60

/**
 * Input shape for buildPersistentWorkspaceName.
 */
export interface BuildWorkspaceNameInput {
  userId: string
  repoId: string
  branchKey: string
  mode: 'interactive' | 'keepalive'
}

/**
 * Build a deterministic, URL-safe workspace name for a named persistent
 * sandbox.  The name is used as the `name` parameter in Sandbox.get({ name }).
 *
 * Naming scheme (from the plan):
 *   user-{userId}-repo-{repoId}-branch-{branchKey}-mode-{mode}
 *
 * IMPORTANT: Never include secrets or tokens in the workspace name.
 * The name is visible to Vercel's infrastructure.
 *
 * TODO Phase 2: When segments are long, hash the trailing parts with SHA-256
 * and truncate to keep the total name within MAX_WORKSPACE_NAME_LENGTH.
 * Current stub already enforces the length limit via hashing.
 */
export function buildPersistentWorkspaceName(input: BuildWorkspaceNameInput): string {
  const { userId, repoId, branchKey, mode } = input

  const raw = `user-${userId}-repo-${repoId}-branch-${branchKey}-mode-${mode}`

  if (raw.length <= MAX_WORKSPACE_NAME_LENGTH) {
    return raw
  }

  // When the raw name is too long, hash the variable segments and use a
  // fixed-length prefix so the name stays within the limit.
  // TODO Phase 2: Refine the hashing strategy (prefix length, hash algorithm).
  const hash = createHash('sha256').update(raw).digest('hex').slice(0, 16)
  const prefix = `sb-${mode}`.slice(0, MAX_WORKSPACE_NAME_LENGTH - 17) // leave room for '-' + 16-char hash
  return `${prefix}-${hash}`
}

/**
 * Retrieve an existing named persistent sandbox by workspace name, or create
 * a new one if none exists.
 *
 * Returns the sandbox on success, or null when the persistent sandbox feature
 * is not yet available or the SDK call fails.
 *
 * TODO Phase 2: Call Sandbox.get({ name }) (or equivalent SDK method).
 * Persist the workspace record in sandboxWorkspaces.
 */
export async function tryGetOrCreateByName(_name: string): Promise<null> {
  // Stub: always returns null; persistent workspace implemented in Phase 2.
  return null
}

/**
 * Hand off a sandbox to the persistent workspace pool after a keepAlive task
 * completes.  The sandbox remains running so follow-up tasks can resume it.
 *
 * This is a no-op stub — the real implementation will update the
 * sandboxWorkspaces row and remove the sandbox from the active-task registry.
 *
 * TODO Phase 2: Update sandboxWorkspaces status to 'idle', record lastSeenAt,
 * and remove from sandbox-registry so it is not auto-stopped.
 */
export async function handoffForPersistence(_sandbox: unknown): Promise<void> {
  // Stub: no-op; persistent handoff implemented in Phase 2.
}
