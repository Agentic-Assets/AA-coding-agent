/**
 * SandboxManager — orchestration entry point for the Vercel Sandbox lifecycle.
 *
 * Phase 0 scaffold: all advanced strategies (snapshots, persistent workspaces)
 * are gated behind feature flags and currently stub out to null, causing every
 * path to fall through to the existing createSandbox() / shutdownSandbox()
 * implementations.  With all flags OFF the task pipeline behavior is identical
 * to calling createSandbox() directly.
 *
 * Call sites are NOT changed in Phase 0.  lib/tasks/process-task.ts continues
 * to call createSandbox() directly until Phase 1 migrates it.
 *
 * IMPORTANT: Static strings only in any log / console statements.
 * Never log task IDs, user IDs, repo URLs, branch names, or tokens.
 */

import { Sandbox } from '@vercel/sandbox'
import { createSandbox } from './creation'
import { shutdownSandbox } from './git'
import { isSnapshotsEnabled, isPersistentEnabled } from './feature-flags'
import { tryRestoreForProfile, createIfEligible } from './snapshots'
import { tryGetOrCreateByName, handoffForPersistence } from './persistent'
import type { SetupProfile } from './profiles'
import type { PreparedSandbox, PrepareSandboxInput, ResumeSandboxInput, StopSandboxInput } from './types'

// Re-export the input / result types so callers can import from one place.
export type { PreparedSandbox, PrepareSandboxInput, ResumeSandboxInput, StopSandboxInput }

/**
 * Prepare a sandbox for a new task.
 *
 * Strategy selection (with all flags currently OFF):
 *   isSnapshotsEnabled() → attempt snapshot restore (Phase 1+, currently stub)
 *   else                 → fall through to createSandbox() (current behavior)
 *
 * With flags off the returned PreparedSandbox wraps the SandboxResult from
 * createSandbox() with mode='fresh'.  Behavior is byte-identical to calling
 * createSandbox() directly.
 */
export async function prepareSandboxForTask(taskContext: PrepareSandboxInput): Promise<PreparedSandbox> {
  if (isSnapshotsEnabled()) {
    // Phase 1+: attempt to restore from a matching snapshot.
    // computeSetupProfileKey is not wired yet — use a stub key.
    const profileKey = 'profile:stub'
    const restored = await tryRestoreForProfile(profileKey)

    if (restored !== null) {
      // Snapshot restore succeeded — wrap in PreparedSandbox.
      // TODO Phase 1: build the real PreparedSandbox from the restored sandbox.
      // For now this branch is unreachable (tryRestoreForProfile always returns null).
    }

    // Fall through to fresh creation when restore returns null.
  }

  // Default path: delegate to the existing createSandbox() implementation.
  const sandboxResult = await createSandbox(taskContext.sandboxConfig, taskContext.logger)

  return {
    sandboxResult,
    mode: 'fresh',
  }
}

/**
 * Resume a sandbox for a follow-up task (keepAlive / interactive mode).
 *
 * Strategy selection (with all flags currently OFF):
 *   isPersistentEnabled() → try to reuse a named persistent workspace (Phase 2+)
 *   else                  → fall through to prepareSandboxForTask()
 *
 * With flags off this simply delegates to prepareSandboxForTask().
 */
export async function resumeSandboxForTask(taskContext: ResumeSandboxInput): Promise<PreparedSandbox> {
  if (isPersistentEnabled()) {
    // Phase 2+: attempt to reuse a named persistent sandbox.
    // buildPersistentWorkspaceName is not wired yet — use a stub name.
    const workspaceName = `sb-stub-${taskContext.taskId}`
    const existing = await tryGetOrCreateByName(workspaceName)

    if (existing !== null) {
      // Persistent workspace found — wrap in PreparedSandbox.
      // TODO Phase 2: build the real PreparedSandbox from the persistent sandbox.
      // For now this branch is unreachable (tryGetOrCreateByName always returns null).
    }

    // Fall through to fresh creation when persistent lookup returns null.
  }

  // Default path: same as a fresh prepare.
  return prepareSandboxForTask(taskContext)
}

/**
 * Snapshot the sandbox after setup completes, if eligible.
 *
 * With flags off this is always a no-op returning null.
 * Phase 1 will wire the real eligibility check and SDK call.
 */
export async function snapshotSandboxIfEligible(_sandbox: Sandbox, _profile: SetupProfile): Promise<string | null> {
  if (!isSnapshotsEnabled()) {
    return null
  }

  // Phase 1+: profileKey will be computed from the real profile.
  const profileKey = 'profile:stub'
  const sandboxId = 'sandbox:stub'

  // createIfEligible is currently a stub that always returns null.
  return createIfEligible(sandboxId, profileKey)
}

/**
 * Stop the sandbox or hand it off to the persistent pool.
 *
 * With flags off this always calls shutdownSandbox() (existing behavior).
 * Phase 2 will wire the persistent handoff path.
 */
export async function stopOrPersistSandbox(taskContext: StopSandboxInput, sandbox: Sandbox): Promise<void> {
  if (isPersistentEnabled() && taskContext.keepAlive) {
    // Phase 2+: hand off to persistent workspace pool so the sandbox stays
    // alive for follow-up tasks.
    await handoffForPersistence(sandbox)
    return
  }

  // Default path: shut down immediately (existing behavior).
  await shutdownSandbox(sandbox)
}
