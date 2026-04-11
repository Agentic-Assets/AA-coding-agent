/**
 * Sandbox health probes and error classification stubs.
 *
 * Phase 0 scaffold — all functions are stubs.
 * Real implementations land in Phase 1+ when snapshot restore is wired.
 */

/**
 * Returns true if the sandbox is healthy and responsive.
 *
 * TODO: Real implementation should run a lightweight echo command (e.g. `echo ok`)
 * and verify exit code 0 within a short timeout (< 5 s). Any exception or
 * non-zero exit should return false.
 */
export async function isSandboxHealthy(_sandbox: unknown): Promise<boolean> {
  // Stub: always report healthy until real probe is implemented.
  return true
}

/**
 * Classifies a restore error into a known category so callers can decide
 * whether to retry, fallback to a fresh sandbox, or surface to the user.
 *
 * TODO: Real implementation should inspect the error message and error codes
 * returned by the Vercel Sandbox SDK to distinguish:
 *   'stale'   — snapshot exists but its content is too old / mismatched
 *   'missing' — snapshot id not found in Vercel's registry
 *   'unknown' — unclassified error; safest to fall through to fresh creation
 */
export function classifyRestoreError(_error: unknown): 'stale' | 'missing' | 'unknown' {
  // Stub: treat all errors as unknown until classification logic is implemented.
  return 'unknown'
}
