# Sandbox Telemetry Reference

## Purpose

The sandbox telemetry layer (`lib/sandbox/telemetry.ts`) emits structured timing and status events for each phase of the sandbox lifecycle. Its purpose is to measure the cold-path performance of sandbox setup operations (creation, dependency installation, dev server readiness) without collecting personally identifiable information or sensitive data.

**What it is:** A lightweight, static-logging-safe metrics collection layer that tracks phase duration, success/failure status, and optional execution context (mode, profile, snapshot ID).

**What it is NOT:** A comprehensive distributed tracing system; it's scoped to sandbox-specific operations and does not collect logs, error details, user info, repository names, or branch names.

## Phase Taxonomy

The telemetry system defines eight lifecycle phases, with Phase 0 implementation covering only the first three:

| Phase | What It Measures | Emitted By | Phase 0 Coverage |
|-------|------------------|-----------|------------------|
| `sandbox.create` | Time to provision Vercel sandbox container | `lib/sandbox/creation.ts:107` | Fully wired via `measureSandboxPhase()` |
| `sandbox.clone` | Time to clone repository and checkout branch | (stub) | Planned Phase 1 |
| `sandbox.deps.install` | Time to install Node.js dependencies (npm/pnpm/yarn) | `lib/sandbox/creation.ts:285` | Partially wired (Node.js path only; Python/pip path is a stub) |
| `sandbox.devserver.ready` | Time to launch dev server and confirm port availability | `lib/sandbox/creation.ts:417` | Fully wired via manual timer + sleep-based check |
| `sandbox.snapshot.build` | Time to build and store sandbox snapshot | (stub in `lib/sandbox/snapshots.ts`) | Deferred to Phase 1 |
| `sandbox.snapshot.restore` | Time to restore sandbox from snapshot | (stub in `lib/sandbox/snapshots.ts`) | Deferred to Phase 1 |
| `sandbox.persistent.reconnect` | Time to reconnect to a persistent named workspace | (stub in `lib/sandbox/persistent.ts`) | Deferred to Phase 2 |
| `sandbox.task.total` | Total end-to-end task duration (all phases combined) | (stub) | Deferred to Phase 1+ |

## Event Shape

```typescript
interface SandboxLifecycleEvent {
  phase: SandboxLifecyclePhase
  durationMs: number
  status: 'success' | 'failure' | 'skipped'
  mode: 'fresh' | 'snapshot' | 'persistent'
  profileKey?: string     // Phase 1+: Profile fingerprint for snapshot matching
  snapshotId?: string     // Phase 1+: Vercel snapshot ID reference
  workspaceName?: string  // Phase 2+: Named persistent workspace identifier
  errorClass?: string     // Error classifier: 'TimeoutError', 'NetworkError', 'unknown'
}
```

**Privacy Contract — Explicitly Forbidden Fields:**
- `repoUrl`, `branchName` — Repository and branch identifiers
- `userId` — User identification
- `rawErrorMessage` — Raw error text (use `errorClass` for type only)
- No dynamic or sensitive values

**Rationale:** Telemetry events are logged via `console.info` and may appear in observability pipelines. Static-logging rule enforced: first argument to `console.info` must be a static string (`'[sandbox.telemetry]'`); the event object is the second argument, not interpolated. This prevents accidental secrets leakage.

## API Surface

### `startSandboxPhaseTimer(phase: SandboxLifecyclePhase): PhaseTimer`

Manual timer management for phases where wrapping is not practical.

```typescript
const timer = startSandboxPhaseTimer('sandbox.devserver.ready')
// ... perform operation ...
emitSandboxLifecycleEvent(timer.stop({ status: 'success', mode: 'fresh' }))
```

**When to use:** Direct control over timing boundaries; async operations with cleanup logic; operations that may be skipped conditionally.

**Error handling:** No exceptions thrown; returns event object on `.stop()` which must be passed to `emitSandboxLifecycleEvent()`.

### `emitSandboxLifecycleEvent(event: SandboxLifecycleEvent): void`

Emit a telemetry event to the configured sink.

```typescript
console.info('[sandbox.telemetry]', JSON.stringify(event))
```

**Current Phase 0 sink:** `console.info` with static prefix. No database persistence yet.

**When to use:** After `.stop()` returns; always pair with a timer.

**Error handling:** Silently swallows errors if `JSON.stringify(event)` fails (rare; would only occur if a field contained a circular reference).

### `measureSandboxPhase<T>(phase: SandboxLifecyclePhase, fn: () => Promise<T>, options?: {...}): Promise<T>`

Convenience wrapper: start timer, execute async function, emit success/failure event, re-throw error.

```typescript
const result = await measureSandboxPhase('sandbox.create', () => Sandbox.create(config), {
  mode: 'fresh',
  errorClassifier: (err) => err instanceof TimeoutError ? 'TimeoutError' : 'unknown'
})
```

**When to use:** Wrapping async operations where error propagation is the default behavior (never swallows exceptions).

**Error handling:** On exception, captures `errorClass` via optional `errorClassifier` callback (defaults to `'unknown'`); re-throws the original error so callers see no behavior change. Always emits an event before re-throwing.

## Static-Logging Contract

The telemetry sink uses this pattern:

```typescript
console.info('[sandbox.telemetry]', JSON.stringify(event))
```

- **First argument**: Always the static string `'[sandbox.telemetry]'` — never a template literal.
- **Second argument**: The event object (non-interpolated), so `JSON.stringify` captures the full structure safely.

This satisfies the static-logging rule: the console call has no dynamic values in the prefix argument, preventing accidental exposure of secrets or PII.

**Example:**
```typescript
// GOOD - static first arg
console.info('[sandbox.telemetry]', JSON.stringify(event))

// BAD - do not do this
console.info(`[sandbox.telemetry] phase=${event.phase}`)
```

## Phase 1 Handoff

Phase 1 implementers should:

1. **Durable Sink**: Replace the `console.info` output with database persistence to `sandbox_snapshots` table (`buildDurationMs`, `restoreDurationMs` columns) and/or OpenTelemetry export.

2. **Snapshot Phases**: Implement `sandbox.snapshot.build` and `sandbox.snapshot.restore` in `lib/sandbox/snapshots.ts`. Replace the `Promise<null>` stubs with actual telemetry emission:
   - `sandbox.snapshot.build` — measure time to serialize and store snapshot
   - `sandbox.snapshot.restore` — measure time to hydrate sandbox from snapshot

3. **Clone Phase**: Instrument `sandbox.clone` in `creation.ts` (currently a stub). Measure Git clone + checkout time separately from sandbox creation.

4. **Deps Install Coverage**: Extend `sandbox.deps.install` to cover Python/pip path (currently only Node.js path is instrumented). Emit telemetry for pip install as well.

5. **Dev Server Readiness Check**: Replace the 3-second sleep in `devserver.ready` check with an actual port probe (TCP connection attempt to localhost:<port>) to get real timing.

6. **Task Total**: Implement `sandbox.task.total` to measure end-to-end execution from sandbox creation through Git push (requires coordination across `process-task.ts`).

See `docs/VERCEL_SANDBOX_MODERNIZATION_PLAN.md` for the full Phase 1 roadmap and timeline.

## Known Limitations

1. **Zero-Duration Events**: Events with `durationMs === 0` may be skipped by downstream sinks if configured for minimum threshold filtering. Consider rounding to `Math.max(1, durationMs)` if needed.

2. **Partial Coverage — `sandbox.deps.install`**: Only Node.js package managers (npm, pnpm, yarn) are instrumented. Python/pip path is a stub and emits no telemetry in Phase 0.

3. **Silent Error Swallowing**: If an event object contains a circular reference (highly unlikely), `JSON.stringify(event)` will throw and the error is silently swallowed. Future Phase 1+ sinks should wrap `JSON.stringify` in try-catch and log non-fatal errors separately.

4. **No Session Correlation**: Events are emitted independently; there is no correlation ID linking all phases of a single sandbox lifecycle. Phase 1 should add a `sandboxId` field for tracing a complete execution.

5. **Mode Always 'fresh' in Phase 0**: The `mode` field is hardcoded to `'fresh'` until Phase 1 implements snapshot/persistent modes. No distinction between cold-start and resumed sandboxes today.
