/**
 * Phase-gated feature flags for Vercel Sandbox modernization.
 * All flags default OFF except SANDBOX_USE_NODE24_DEFAULT which is opt-OUT
 * to match the new SDK default runtime of node24.
 *
 * Phase 0 Task 4: introduces these flags — none are wired except node24 default.
 * Snapshot, persistent, and network-policy flags are placeholders for later phases.
 */

/**
 * Enable snapshot-based sandbox creation (Phase 1+).
 * Default: OFF
 */
export function isSnapshotsEnabled(): boolean {
  return process.env.SANDBOX_ENABLE_SNAPSHOTS === '1'
}

/**
 * Enable persistent (named) sandbox support (Phase 2+, requires SDK beta).
 * Default: OFF
 */
export function isPersistentEnabled(): boolean {
  return process.env.SANDBOX_ENABLE_PERSISTENT === '1'
}

/**
 * Enable network policy configuration on sandbox creation (Phase 1+).
 * Default: OFF
 */
export function isNetworkPolicyEnabled(): boolean {
  return process.env.SANDBOX_ENABLE_NETWORK_POLICY === '1'
}

/**
 * Use node24 as the default sandbox runtime when no runtime is explicitly configured.
 * This is opt-OUT (default ON) to match the @vercel/sandbox 1.9.3 SDK default.
 * Set SANDBOX_USE_NODE24_DEFAULT=0 to fall back to node22.
 * Default: ON
 */
export function isNode24DefaultEnabled(): boolean {
  return process.env.SANDBOX_USE_NODE24_DEFAULT !== '0'
}
