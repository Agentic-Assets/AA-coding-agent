/**
 * Setup profile fingerprint helpers.
 *
 * A SetupProfile captures all inputs that affect sandbox setup so that
 * identical setups can share a snapshot.  The key must be deterministic,
 * stable across restarts, and MUST NOT encode user identity or secrets.
 *
 * Phase 0 scaffold — key computation and DB helpers are stubs.
 * Real implementations land in Phase 1+.
 */

import { sandboxProfiles } from '@/lib/db/schema'

// Re-export the Drizzle table for type reference in other modules.
// DO NOT query it yet — Phase 1 wires the real lookup/upsert.
export { sandboxProfiles }

/**
 * Bump this constant whenever the setup pipeline changes in a breaking way
 * (e.g. new tool installed, different clone strategy).  Changing the version
 * automatically invalidates all existing profiles/snapshots for the new code.
 */
export const SETUP_SCHEMA_VERSION = 1

/**
 * All inputs that contribute to a sandbox setup fingerprint.
 *
 * Fields marked TODO are not yet populated by the call sites;
 * they will be filled in as Phase 1 wires real profile computation.
 *
 * IMPORTANT: This type MUST NOT include userId, tokens, secrets, or any
 * per-user credential.  The profile key must be safely shareable across
 * users who set up the same repo with the same tooling.
 */
export interface SetupProfile {
  /** Vercel Sandbox runtime, e.g. 'node24' | 'node22' | 'python3.13' */
  runtime: string

  /** Detected package manager: 'npm' | 'pnpm' | 'yarn' | null */
  packageManager: string | null

  /**
   * SHA-256 hex digest of the lockfile content (package-lock.json,
   * pnpm-lock.yaml, or yarn.lock).  null when no lockfile is present.
   * TODO: computed during dependency detection in Phase 1
   */
  lockfileHash: string | null

  /**
   * Canonical repo identity string, e.g. 'github.com/owner/repo'.
   * Strip the scheme and trailing '.git' before encoding.
   * TODO: normalised in Phase 1 call sites
   */
  repoIdentity: string

  /**
   * Version string of the agent tooling installed in the snapshot
   * (e.g. Claude Code CLI version).  null for snapshots created before
   * agent tooling was captured.
   * TODO: populated in Phase 1 after CLI install step
   */
  agentToolingVersion: string | null

  /**
   * Must equal SETUP_SCHEMA_VERSION.  Included in key so that bumping the
   * constant automatically invalidates old profiles without a migration.
   */
  setupSchemaVersion: number
}

/**
 * Input shape for computeSetupProfileKey.
 * Identical to SetupProfile — kept as a separate alias so callers can pass
 * partial data as Phase 1 fills in fields incrementally.
 */
export type SetupProfileInput = SetupProfile

/**
 * Compute a deterministic, stable string key from a SetupProfileInput.
 *
 * The key is used to look up matching snapshots in the DB.
 *
 * CONSTRAINTS (never violate):
 *   - MUST NOT include userId, GitHub tokens, API keys, or any secret.
 *   - MUST be deterministic: same input → same output across restarts.
 *   - MUST change when SETUP_SCHEMA_VERSION bumps.
 *
 * TODO Phase 1: Replace the stub with a real implementation that:
 *   1. Sorts all fields alphabetically.
 *   2. JSON-serialises the sorted object.
 *   3. Returns `sha256(serialised).hex()` truncated to 64 chars or similar.
 */
export function computeSetupProfileKey(_input: SetupProfileInput): string {
  // TODO: implement deterministic SHA-256 fingerprint in Phase 1.
  return 'profile:stub'
}

/**
 * Look up an existing profile row by its key.
 *
 * TODO Phase 1: Replace with `db.select().from(sandboxProfiles).where(eq(sandboxProfiles.profileKey, key))`.
 * Returns null when no matching profile exists.
 */
export async function findProfileByKey(_key: string): Promise<null> {
  // TODO: query sandboxProfiles table in Phase 1.
  return null
}

/**
 * Insert or update a profile row.
 *
 * TODO Phase 1: Replace with an upsert on sandboxProfiles using profileKey as
 * the conflict target.  Return the persisted row.
 */
export async function upsertProfile(_profile: SetupProfileInput): Promise<null> {
  // TODO: write to sandboxProfiles table in Phase 1.
  return null
}
