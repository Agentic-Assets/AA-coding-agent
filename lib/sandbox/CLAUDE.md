# Sandbox Module

## Domain Purpose
Orchestrate Vercel sandbox lifecycle: creation, environment setup, dependency detection, Git configuration, and agent execution orchestration.

## Module Boundaries
- **Owns**: Repository cloning, project type detection, dependency installation, dev server launch, sandbox registry
- **Delegates to**: `agents/` for AI agent execution, `commands.ts` for Vercel SDK operations, `git.ts` for push operations, `package-manager.ts` for detection/installation

## Local Patterns
- **Cancellation Strategy**: 5-stage checks (pre-creation, post-creation, post-deps, pre-git, pre-agent); non-blocking via callback
- **Progress Tracking**: onProgress(percentage, message) callback for UI synchronization
- **Package Managers**: Detect npm/pnpm/yarn; handle multi-fallback for Python pip
- **Dev Server Patterns**: Next.js requires `--webpack` flag; Vite requires `host: true` to disable DNS checking
- **Empty Repos**: Initialize with README to prevent agent startup issues
- **Shallow Clones**: Use `--depth 1` for large repos; timeout after 5 minutes

## Integration Points
- `app/api/tasks/route.ts` - Calls `createSandbox()` at task start
- `lib/sandbox/agents/index.ts` - `executeAgentInSandbox()` after sandbox ready
- `lib/sandbox/git.ts` - `pushChangesToBranch()` after agent completes
- `lib/utils/task-logger.ts` - Real-time log streaming
- `lib/sandbox/sandbox-registry.ts` - Track active sandboxes for cleanup

## Key Files
- `creation.ts` - Main `createSandbox()` function (700+ lines)
- `commands.ts` - Sandbox command execution wrappers
- `package-manager.ts` - npm/pnpm/yarn detection and installation
- `git.ts` - `pushChangesToBranch()`, `shutdownSandbox()` for post-agent Git operations
- `sandbox-registry.ts` - `registerSandbox()`, `unregisterSandbox()`, `getSandbox()`, `killSandbox()` for lifecycle tracking
- `types.ts` - AgentExecutionResult, CancellationCheckFn type definitions
- `config.ts`, `port-detection.ts` - Configuration and port detection utilities
- `feature-flags.ts` - Phase 0 feature flags (snapshots, persistent, network-policy, node24-default)
- `telemetry.ts` - Lifecycle event emission with 8-phase taxonomy
- `manager.ts` - Sandbox orchestration layer (Phase 0 stub delegating to creation.ts/git.ts)
- `profiles.ts` - Setup profile fingerprinting for snapshot matching (Phase 0 stub)
- `snapshots.ts` - Snapshot registry helpers (Phase 0 stub)
- `persistent.ts` - Named persistent sandbox helpers (Phase 0 stub)
- `health.ts` - Health checks and restore-error classifier (Phase 0 stub)

## Phase 0 Status
Task 2 scaffolded `manager.ts`, `profiles.ts`, `snapshots.ts`, `persistent.ts`, `health.ts` as stubs; Task 5 added `telemetry.ts` and instrumentation in `creation.ts`. All new modules delegate to existing `creation.ts` and `git.ts` during Phase 0. Phase 1 will implement snapshot logic; Phase 2 will implement persistent sandbox support. See `docs/VERCEL_SANDBOX_MODERNIZATION_PLAN.md` for timeline.
