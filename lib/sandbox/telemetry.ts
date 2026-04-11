/**
 * Sandbox lifecycle telemetry — Phase 0 scaffolding.
 *
 * PRIVACY CONTRACT — fields that are explicitly FORBIDDEN from this event shape:
 *   - repoUrl, branchName, userId, rawErrorMessage
 * Only structural / timing data is captured. No secrets, no PII, no paths.
 *
 * TODO Phase 1+: replace emitSandboxLifecycleEvent sink with DB persistence
 * (sandbox_snapshots.buildDurationMs / restoreDurationMs) and optional OTEL export.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * All phases tracked across the sandbox lifecycle.
 * Phase 0 instruments: sandbox.create, sandbox.deps.install, sandbox.devserver.ready
 * Future phases add the rest.
 */
export type SandboxLifecyclePhase =
  | 'sandbox.create'
  | 'sandbox.clone'
  | 'sandbox.deps.install'
  | 'sandbox.devserver.ready'
  | 'sandbox.snapshot.build'
  | 'sandbox.snapshot.restore'
  | 'sandbox.persistent.reconnect'
  | 'sandbox.task.total'

/**
 * A single structured timing metric for one sandbox lifecycle phase.
 *
 * Deliberately omits: repoUrl, branchName, userId, raw error text.
 * Only safe structural + timing fields are recorded.
 */
export interface SandboxLifecycleEvent {
  phase: SandboxLifecyclePhase
  durationMs: number
  status: 'success' | 'failure' | 'skipped'
  /** How the sandbox was obtained. Phase 0 always 'fresh'. */
  mode: 'fresh' | 'snapshot' | 'persistent'
  /** Profile fingerprint key (Phase 1+). */
  profileKey?: string
  /** Vercel snapshot id (Phase 1+). */
  snapshotId?: string
  /** Named workspace identifier (Phase 2+). */
  workspaceName?: string
  /**
   * A short classifier for the error class, NOT the raw error message.
   * E.g. 'TimeoutError', 'NetworkError', 'unknown'.
   */
  errorClass?: string
}

// ---------------------------------------------------------------------------
// PhaseTimer
// ---------------------------------------------------------------------------

export interface PhaseTimerStopOptions {
  status: SandboxLifecycleEvent['status']
  mode?: SandboxLifecycleEvent['mode']
  profileKey?: string
  snapshotId?: string
  workspaceName?: string
  errorClass?: string
}

export interface PhaseTimer {
  stop(result: PhaseTimerStopOptions): SandboxLifecycleEvent
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Start a timer for a sandbox lifecycle phase.
 * Call `.stop()` on the returned object to finalize and get the event.
 */
export function startSandboxPhaseTimer(phase: SandboxLifecyclePhase): PhaseTimer {
  const startedAt = performance.now()

  return {
    stop(result: PhaseTimerStopOptions): SandboxLifecycleEvent {
      const durationMs = Math.round(performance.now() - startedAt)
      return {
        phase,
        durationMs,
        status: result.status,
        mode: result.mode ?? 'fresh',
        profileKey: result.profileKey,
        snapshotId: result.snapshotId,
        workspaceName: result.workspaceName,
        errorClass: result.errorClass,
      }
    },
  }
}

/**
 * Emit a sandbox lifecycle event to the configured sink.
 *
 * Phase 0 sink: structured JSON logged via console.info with a static prefix.
 * The dynamic content is passed as a second argument (not interpolated into the
 * string), which satisfies the static-logging rule.
 *
 * TODO Phase 1+: replace this with DB persistence to
 * `sandbox_snapshots.buildDurationMs` / `restoreDurationMs`
 * and optional OTEL export.
 */
export function emitSandboxLifecycleEvent(event: SandboxLifecycleEvent): void {
  // Static prefix — no template literal interpolation.
  // JSON.stringify(event) is the second arg, not embedded in the string.
  console.info('[sandbox.telemetry]', JSON.stringify(event))
}

/**
 * Convenience wrapper: start a timer, run `fn`, emit success/failure, re-throw.
 *
 * - NEVER swallows the error — callers see no behavior change.
 * - On throw, captures `errorClass` via `options.errorClassifier?.(err)`,
 *   defaulting to 'unknown' if no classifier is provided.
 * - If `fn` is skipped (never called), emit the event with status 'skipped'
 *   from the call site using startSandboxPhaseTimer directly.
 */
export async function measureSandboxPhase<T>(
  phase: SandboxLifecyclePhase,
  fn: () => Promise<T>,
  options?: {
    mode?: SandboxLifecycleEvent['mode']
    profileKey?: string
    snapshotId?: string
    workspaceName?: string
    errorClassifier?: (err: unknown) => string
  },
): Promise<T> {
  const timer = startSandboxPhaseTimer(phase)
  try {
    const result = await fn()
    const event = timer.stop({
      status: 'success',
      mode: options?.mode ?? 'fresh',
      profileKey: options?.profileKey,
      snapshotId: options?.snapshotId,
      workspaceName: options?.workspaceName,
    })
    emitSandboxLifecycleEvent(event)
    return result
  } catch (err: unknown) {
    const errorClass = options?.errorClassifier ? options.errorClassifier(err) : 'unknown'
    const event = timer.stop({
      status: 'failure',
      mode: options?.mode ?? 'fresh',
      profileKey: options?.profileKey,
      snapshotId: options?.snapshotId,
      workspaceName: options?.workspaceName,
      errorClass,
    })
    emitSandboxLifecycleEvent(event)
    // Re-throw so callers see no behavior change.
    throw err
  }
}
