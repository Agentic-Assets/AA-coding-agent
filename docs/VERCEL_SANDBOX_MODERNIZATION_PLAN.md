# Vercel Sandbox Modernization Plan

## Purpose

Modernize the sandbox layer to match Vercel Sandbox capabilities available in April 2026 while keeping the product reliable for many users, many repositories, and many setup shapes.

This plan recommends a hybrid model:

- Use snapshot-backed ephemeral sandboxes as the default execution path.
- Use named persistent sandboxes for interactive and keep-alive workflows behind a feature flag.
- Keep sandbox state, snapshot state, and user secrets clearly separated.

## Executive Summary

The current implementation is functionally correct for isolated execution, but it still pays most cold-start costs on each task:

- fresh sandbox creation
- repo clone
- dependency install
- agent CLI setup
- optional dev server boot

The biggest upgrade is to stop treating every task as a from-scratch environment build.

Recommended target state:

1. Upgrade the sandbox integration to the current SDK line and runtime defaults.
2. Add a sandbox abstraction layer so the app can choose between:
   - fresh ephemeral sandbox
   - snapshot restore
   - named persistent sandbox
3. Introduce a snapshot registry keyed by deterministic setup fingerprints.
4. Use snapshots for reusable setup work.
5. Use named persistent sandboxes only for workflows that truly need continuity.
6. Never snapshot user-specific secrets or auth material.
7. Add strong observability, health checks, and fallback paths so the new system stays robust.

## What We Should Optimize For

- Fast first useful action, not just fast sandbox creation.
- Deterministic setup behavior across users and repositories.
- Safe multi-user isolation.
- Clear fallback behavior when snapshots are stale, missing, or invalid.
- Minimal risk of leaking user-specific credentials into shared artifacts.
- Easy local development and debugging for the sandbox layer.

## Recommended Architecture

### 1. Introduce a `SandboxManager` Layer

Create a single orchestration layer that decides which sandbox strategy to use.

Suggested module layout:

- `lib/sandbox/manager.ts`
- `lib/sandbox/snapshots.ts`
- `lib/sandbox/persistent.ts`
- `lib/sandbox/profiles.ts`
- `lib/sandbox/health.ts`

Core interface:

- `prepareSandboxForTask(taskContext)`
- `resumeSandboxForTask(taskContext)`
- `snapshotSandboxIfEligible(sandbox, profile)`
- `stopOrPersistSandbox(taskContext, sandbox)`

This keeps the rest of the app from caring whether the sandbox came from:

- `Sandbox.create(...)`
- `Sandbox.create({ source: { type: 'snapshot', snapshotId } })`
- `Sandbox.get({ sandboxId })`
- `Sandbox.get({ name })` for persistent sandboxes

### 2. Split Execution Into Three Modes

#### Mode A: Snapshot-Backed Ephemeral Task Sandbox

Use this as the default for most tasks.

Flow:

1. Resolve a setup profile.
2. Look for a valid snapshot for that profile.
3. Restore from snapshot if found.
4. Apply user-specific runtime overlay.
5. Run the agent.
6. Stop the sandbox when done unless the task needs continuity.

Best for:

- one-shot code changes
- background task execution
- multi-agent compare mode
- MCP-triggered jobs

#### Mode B: Named Persistent Sandbox

Use this for keep-alive, follow-up, terminal, and preview-heavy workflows.

Flow:

1. Compute a persistent workspace name.
2. Attempt `Sandbox.get({ name })`.
3. If found, reuse it.
4. If not found, create it from the best available snapshot.
5. Let Vercel handle persistence on stop where supported.

Best for:

- keep-alive sessions
- follow-up chat iterations
- terminal/file editing sessions
- long-lived preview workspaces

#### Mode C: Fresh Sandbox Fallback

Keep a deterministic fallback path when:

- no snapshot exists
- snapshot restore fails
- profile changed
- persistent sandbox is unhealthy
- feature flags disable advanced modes

This preserves reliability during rollout.

## How To Handle Different Users and Different Setups

This is the most important design constraint.

We should not treat "sandbox setup" as a single global cache. We should model it as layered setup state.

### Layer 1: Shared Base Tooling Snapshot

Scope: platform-owned, no user data, no repo data.

Contains:

- base runtime choice
- common OS packages
- common agent CLIs
- common helper scripts

Examples:

- `node24 + claude/codex/copilot/cursor/opencode CLIs`
- `python3.13 + common Python tooling`

This should be safe to share broadly because it contains no user-specific state.

### Layer 2: Repo Setup Snapshot

Scope: per repo setup fingerprint, optionally scoped per user for private repos.

Contains:

- checked-out repo
- installed dependencies
- framework-specific setup
- dev-server-ready filesystem state

This is where most startup savings come from.

### Layer 3: User Runtime Overlay

Scope: per task or per live session, never persisted into shared snapshots.

Contains:

- user API keys
- GitHub token usage
- MCP connector auth
- user-specific agent config
- temporary env overrides

This should be applied after restore and removed before any shared snapshot is created.

### Setup Fingerprint Strategy

Create a deterministic `setupProfileKey` from inputs that materially affect the filesystem and toolchain:

- sandbox mode
- runtime (`node24`, `python3.13`, etc.)
- package manager
- `installDependencies` flag
- lockfile hash
- `package.json` plus framework fingerprint
- repo identity
- source branch or base revision policy
- agent tooling version set
- any required system packages
- internal setup schema version

Do not include:

- raw user IDs in shared keys
- API keys
- OAuth tokens
- connector secrets
- agent session IDs

For private repos, the safest default is:

- user-scoped repo snapshots first
- org-scoped snapshots only with explicit policy and auditability

## Snapshot Policy

### What We Should Snapshot

Snapshot only after deterministic setup is complete:

- runtime booted
- repo materialized
- dependencies installed
- shared toolchain installed
- non-secret config written

This gives the highest restore benefit and avoids fragile snapshots taken during active agent work.

### What We Should Not Snapshot

Do not snapshot:

- user secrets
- Git credentials
- live agent conversations
- temp files that are specific to one task run
- noisy logs
- task-specific preview output

### When To Refresh Snapshots

Invalidate and rebuild when:

- lockfile changes
- runtime changes
- agent CLI version set changes
- package manager changes
- framework detection changes
- setup schema version changes

Suggested policy:

- soft TTL for reuse ranking
- hard expiry aligned to Vercel snapshot expiry
- rebuild asynchronously after a miss or invalidation

## Persistent Sandbox Policy

Use persistent sandboxes only when the product needs continuity.

Recommended rules:

- `keepAlive = false`: ephemeral snapshot-backed sandbox
- `keepAlive = true`: named persistent sandbox
- follow-up message on active task: try live persistent sandbox first
- follow-up message on expired task: restore from latest valid snapshot, then continue

Naming scheme:

- `user-{userId}-repo-{repoId}-branch-{branchKey}-mode-interactive`

If the name becomes too long, hash the trailing segments.

## Security and Secret Handling

### Secret Rule

No shared snapshot should ever contain user secrets.

Implementation rules:

- inject user secrets at runtime only
- keep shared snapshot creation separate from user overlay
- scrub or avoid writing auth-bearing config before snapshot creation
- prefer runtime env injection or request-time credential brokering

### Network Policy

Adopt a stricter network lifecycle:

1. open or allow required egress during setup
2. tighten to least privilege before untrusted agent execution
3. explicitly allow model providers, GitHub, npm or package mirrors only when needed

This should be introduced carefully because some agent workflows legitimately need outbound access.

## Runtime and SDK Recommendations

### Recommended Runtime Defaults

- Move Node sandboxes to `node24` by default.
- Keep `python3.13` for Python flows.
- Preserve explicit runtime selection in profile keys.

### Recommended SDK Strategy

Use a versioned rollout:

1. Upgrade to the current stable SDK for snapshot support and newer APIs.
2. Add a feature-flagged path for persistent sandboxes if the product is comfortable adopting beta capabilities.

Suggested feature flags:

- `SANDBOX_ENABLE_SNAPSHOTS`
- `SANDBOX_ENABLE_PERSISTENT`
- `SANDBOX_ENABLE_NETWORK_POLICY`
- `SANDBOX_USE_NODE24_DEFAULT`

## Use the Sandbox CLI for Development

Yes, we should use the Sandbox CLI during development and rollout.

Primary recommendation:

- Use the current `vercel sandbox` workflow for day-to-day debugging.

Fallback or beta-only cases:

- If a required beta feature is only exposed in the beta CLI path, keep a narrow beta-only workflow for those commands.

Recommended developer tasks:

- create test sandboxes
- inspect snapshot restore times
- verify persistent sandbox behavior
- benchmark cold vs warm startup
- reproduce restore failures outside the app
- validate runtime and port behavior

Add helper scripts under `scripts/` for repeatable debugging:

- `scripts/sandbox/dev-create.sh`
- `scripts/sandbox/dev-snapshot.sh`
- `scripts/sandbox/dev-restore.sh`
- `scripts/sandbox/dev-persistent.sh`
- `scripts/sandbox/dev-benchmark.sh`

## Database and Data Model Changes

Add a new snapshot metadata table, for example:

- `sandbox_profiles`
- `sandbox_snapshots`
- `sandbox_workspaces`

Suggested fields for `sandbox_profiles`:

- `id`
- `profileKey`
- `scopeType`
- `scopeOwnerId`
- `repoUrl`
- `runtime`
- `packageManager`
- `lockfileHash`
- `setupVersion`
- `createdAt`
- `updatedAt`

Suggested fields for `sandbox_snapshots`:

- `id`
- `profileId`
- `snapshotId`
- `status`
- `createdFromRuntime`
- `expiresAt`
- `lastUsedAt`
- `restoreCount`
- `buildDurationMs`
- `restoreDurationMs`
- `validationState`

Suggested fields for `sandbox_workspaces`:

- `id`
- `workspaceName`
- `taskId`
- `userId`
- `repoUrl`
- `sandboxId`
- `currentSnapshotId`
- `mode`
- `status`
- `lastSeenAt`

Extend `tasks` as needed with:

- `sandboxMode`
- `setupProfileKey`
- `snapshotId`
- `persistentWorkspaceName`

## Code Changes by Area

### Package and Config

- update [package.json](/Users/cayman-mac-mini/Documents/GitHub/AA-coding-agent/package.json)
- add new env flags to docs and deployment config

### Sandbox Core

- refactor [lib/sandbox/creation.ts](/Users/cayman-mac-mini/Documents/GitHub/AA-coding-agent/lib/sandbox/creation.ts)
- extend [lib/sandbox/types.ts](/Users/cayman-mac-mini/Documents/GitHub/AA-coding-agent/lib/sandbox/types.ts)
- replace or wrap [lib/sandbox/sandbox-registry.ts](/Users/cayman-mac-mini/Documents/GitHub/AA-coding-agent/lib/sandbox/sandbox-registry.ts)
- add snapshot and persistent workspace helpers

### Task Orchestration

- update [lib/tasks/process-task.ts](/Users/cayman-mac-mini/Documents/GitHub/AA-coding-agent/lib/tasks/process-task.ts)
- update follow-up and keep-alive logic

### API Routes

- update [app/api/tasks/route.ts](/Users/cayman-mac-mini/Documents/GitHub/AA-coding-agent/app/api/tasks/route.ts)
- update [app/api/tasks/[taskId]/start-sandbox/route.ts](/Users/cayman-mac-mini/Documents/GitHub/AA-coding-agent/app/api/tasks/[taskId]/start-sandbox/route.ts)
- update stop and health routes
- add admin or debug endpoints only if needed

### Schema

- update [lib/db/schema.ts](/Users/cayman-mac-mini/Documents/GitHub/AA-coding-agent/lib/db/schema.ts)
- add migrations for snapshot and workspace metadata

### UI

- show sandbox mode and restore source in task details
- show whether a task resumed from:
  - live sandbox
  - persistent sandbox
  - snapshot
  - fresh build
- show clearer keep-alive semantics in the form

## Rollout Plan

### Phase 0: Preparation

- upgrade SDK integration behind flags
- add new data model
- add observability for sandbox lifecycle timing
- add benchmark harness

Exit criteria:

- current flow still works unchanged with flags off

### Phase 1: Snapshot-Backed Ephemeral Sandboxes

- implement setup profile generation
- create snapshot registry
- snapshot after deterministic setup
- restore from snapshot on future compatible runs
- fall back to fresh setup on any restore issue

Exit criteria:

- significant reduction in median task startup time
- no regression in task success rate

### Phase 2: Persistent Sandboxes for Keep-Alive

- introduce named persistent sandbox path
- restrict it to keep-alive and interactive sessions
- add health and auto-reconnect logic
- document expiration and recovery behavior

Exit criteria:

- follow-up tasks avoid rebuild in the common case
- preview and terminal workflows become more stable

### Phase 3: Security and Secret Hygiene

- split shared setup from user overlay
- tighten network policy where safe
- verify snapshots never capture user secrets

Exit criteria:

- secret review completed
- snapshot artifacts validated as safe

### Phase 4: Developer Experience

- add CLI-driven debug scripts
- add docs for benchmarking and reproducing sandbox issues
- add local procedures for snapshot and persistent workflow testing

Exit criteria:

- sandbox regressions are easy to reproduce locally

## Observability and SLOs

Track at least:

- sandbox create duration
- snapshot build duration
- snapshot restore duration
- dependency install duration
- dev server ready duration
- task success rate by sandbox mode
- restore hit rate
- restore failure rate
- persistent reconnect success rate

Suggested product goals:

- cut median task environment preparation time by at least 50%
- make warm restore the dominant path for repeat tasks
- keep sandbox-mode regression rate low enough that fallback-to-fresh remains exceptional

## Recommended Final Product Semantics

### Default Task

- fast snapshot-backed ephemeral sandbox
- safe, cheap, repeatable

### Keep Alive Task

- named persistent sandbox
- durable workspace semantics
- better fit for iteration and previews

### Compare Mode

- ephemeral snapshot-backed sandboxes only
- no persistence by default

### Follow-Up Message

Try in this order:

1. live sandbox by id
2. persistent sandbox by name
3. latest compatible snapshot
4. fresh rebuild

## Practical Recommendation

If we want the best April 2026 architecture without over-risking the product:

1. Implement stable snapshots first.
2. Move the default runtime to `node24`.
3. Add a setup profile and snapshot registry.
4. Use persistent sandboxes only for keep-alive and interactive sessions behind a feature flag.
5. Keep fresh rebuild as a hard fallback forever.
6. Use the Sandbox CLI and `vercel sandbox` tooling to benchmark every phase before rollout.

This sequence gives the biggest speed win early while keeping the system robust for different users, repositories, and setup shapes.

## Helpful Vercel Docs

Use these as the primary references during implementation:

- Vercel Sandbox overview: `https://vercel.com/docs/vercel-sandbox`
- Vercel Sandbox SDK reference: `https://vercel.com/docs/vercel-sandbox/sdk-reference`
- Vercel Sandbox snapshots concept doc: `https://vercel.com/docs/vercel-sandbox/concepts/snapshots`
- Vercel blog post on snapshot optimization: `https://vercel.com/blog/optimizing-vercel-sandbox-snapshots`
- Vercel changelog for persistent sandboxes beta: `https://vercel.com/changelog/vercel-sandbox-persistent-sandboxes-beta`
- Vercel changelog for Sandbox CLI availability: `https://vercel.com/changelog/vercel-sandbox-cli-is-now-available`
- Vercel Sandbox GitHub repository: `https://github.com/vercel/sandbox`

Recommended reading order:

1. overview
2. SDK reference
3. snapshots concept doc
4. persistent sandboxes changelog
5. snapshot optimization blog post
6. Sandbox CLI changelog

## Helpful Skills

These are the most helpful Codex skills for this effort.

### Primary Skills

- `vercel:vercel-sandbox`
  - Use for all SDK, runtime, snapshot, and persistent sandbox decisions.
- `vercel:vercel-cli`
  - Use when adding or documenting CLI-based sandbox workflows for development and debugging.
- `vercel:vercel-api`
  - Use when the implementation needs live Vercel project, deployment, or platform context.
- `vercel:investigation-mode`
  - Use when a restore flow, persistent sandbox reconnect, or runtime behavior is failing and needs systematic debugging.

### Supporting Skills

- `ai-sdk`
  - Use if agent orchestration or tool-calling behavior changes affect how coding agents interact with the sandbox layer.
- `mcp-builder`
  - Use if sandbox controls or metadata need to be exposed cleanly through MCP.
- `doc-coauthoring`
  - Use when converting this plan into long-form implementation docs, specs, or rollout notes.

## Helpful Subagents

These are the most useful specialist subagents for implementing the modernization plan.

### Primary Vercel Plugin Agent For AI Architecture

- `ai-architect`
  - Use this as the primary agent for AI-related architecture work when it is available in the current session.
  - Best for:
    - AI application architecture decisions
    - agent orchestration design
    - model/provider selection
    - streaming architecture
    - MCP integration strategy
    - deciding when to use simple generation, agents, or durable workflows

### Repo Specialist Agents

- `sandbox-agent-manager`
  - Best for refactoring the sandbox lifecycle, creation flow, reconnect flow, and keep-alive behavior.
- `agent-expert`
  - Best for changes that affect how Claude, Codex, Cursor, Copilot, Gemini, and OpenCode are launched or resumed.
- `security-logging-enforcer`
  - Best for protecting secrets and ensuring snapshot or runtime logs do not leak sensitive data.
- `security-expert`
  - Best for reviewing snapshot safety, user-secret handling, credential brokering, and network policy changes.
- `docs-maintainer`
  - Best for keeping README, docs, and rollout notes aligned with the new architecture.

### Good Supporting Specialists

- `api-route-architect`
  - Best for changes to task routes such as start, stop, continue, sandbox health, and future sandbox metadata endpoints.
- `database-schema-optimizer`
  - Best for adding snapshot metadata tables, workspace tables, and task-level sandbox state fields.
- `senior-code-reviewer`
  - Best for pre-merge review of the rollout, especially around regressions and safety gaps.

## Suggested Subagent Use By Phase

- Phase 0:
  - `ai-architect`
  - `sandbox-agent-manager`
  - `database-schema-optimizer`
- Phase 1:
  - `ai-architect`
  - `sandbox-agent-manager`
  - `agent-expert`
- Phase 2:
  - `ai-architect`
  - `sandbox-agent-manager`
  - `api-route-architect`
- Phase 3:
  - `ai-architect`
  - `security-expert`
  - `security-logging-enforcer`
- Phase 4:
  - `docs-maintainer`
  - `senior-code-reviewer`
