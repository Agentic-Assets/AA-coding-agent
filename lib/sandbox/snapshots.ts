/**
 * Snapshot registry stubs.
 *
 * These functions will wrap the Vercel Sandbox SDK snapshot APIs in Phase 1.
 * In Phase 0 every function is a safe no-op / always-returns-null stub so
 * that the SandboxManager can import them without affecting the task pipeline.
 *
 * IMPORTANT: Do NOT add dynamic values to any log statements here.
 * Static strings only per project security policy.
 */

// Import the Drizzle table for type reference.
// DO NOT query it yet — real reads/writes land in Phase 1+.
import { sandboxSnapshots } from '@/lib/db/schema'

// Re-export for consumers that need the table type.
export { sandboxSnapshots }

/**
 * Attempt to restore a sandbox from the most recent valid snapshot for the
 * given profile key.
 *
 * Returns the restored sandbox on success, or null when no usable snapshot
 * exists (or snapshots are disabled).
 *
 * TODO Phase 1: Query sandboxSnapshots for status='ready' AND
 * validationState != 'invalid' AND (expiresAt IS NULL OR expiresAt > NOW())
 * ordered by createdAt DESC LIMIT 1, then call Sandbox.restore({ snapshotId }).
 */
export async function tryRestoreForProfile(_profileKey: string): Promise<null> {
  // Stub: always returns null; snapshot restore implemented in Phase 1.
  return null
}

/**
 * Create a snapshot of the given sandbox and register it in the DB if the
 * sandbox is eligible (e.g. setup completed without errors).
 *
 * Returns the Vercel snapshot id on success, or null if ineligible / failed.
 *
 * TODO Phase 1: Call sandbox.snapshot() (or equivalent SDK method), persist
 * the resulting snapshotId into sandboxSnapshots, and return the id.
 */
export async function createIfEligible(_sandboxId: string, _profileKey: string): Promise<null> {
  // Stub: always returns null; snapshot creation implemented in Phase 1.
  return null
}

/**
 * Returns true if the given error represents a snapshot restore failure
 * that should be caught and handled (versus re-thrown).
 *
 * TODO Phase 1: Inspect error.message / error.code for patterns like
 * 'snapshot not found', '404', 'expired', etc.
 */
export function isRestoreFailure(_error: unknown): boolean {
  // Stub: always returns false; classification implemented in Phase 1.
  return false
}
