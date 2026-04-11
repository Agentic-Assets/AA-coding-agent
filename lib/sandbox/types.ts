import { Sandbox } from '@vercel/sandbox'
import { LogEntry } from '@/lib/db/schema'
import type { createSandbox } from './creation'
import type { TaskLogger } from '@/lib/utils/task-logger'

export interface SandboxConfig {
  taskId: string
  repoUrl: string
  githubToken?: string | null
  gitAuthorName?: string
  gitAuthorEmail?: string
  apiKeys?: {
    OPENAI_API_KEY?: string
    GEMINI_API_KEY?: string
    CURSOR_API_KEY?: string
    ANTHROPIC_API_KEY?: string
    AI_GATEWAY_API_KEY?: string
  }
  timeout?: string
  ports?: number[]
  runtime?: string
  resources?: {
    vcpus?: number
  }
  taskPrompt?: string
  selectedAgent?: string
  selectedModel?: string
  installDependencies?: boolean
  keepAlive?: boolean
  preDeterminedBranchName?: string
  /** Source branch to clone from (defaults to repository default branch if not specified) */
  sourceBranch?: string
  onProgress?: (progress: number, message: string) => Promise<void>
  onCancellationCheck?: () => Promise<boolean>
}

export interface SandboxResult {
  success: boolean
  sandbox?: Sandbox
  domain?: string
  branchName?: string
  error?: string
  cancelled?: boolean
}

export interface AgentExecutionResult {
  success: boolean
  output?: string
  agentResponse?: string
  cliName?: string
  changesDetected?: boolean
  error?: string
  streamingLogs?: unknown[]
  logs?: LogEntry[]
  sessionId?: string // For Cursor agent session resumption
}

// ============================================================
// SandboxManager types — Phase 0 scaffold
// Wired into the task pipeline in Phase 1+.
// ============================================================

/**
 * The mode in which a prepared sandbox was obtained.
 *   'fresh'      — a brand-new sandbox created via createSandbox()
 *   'snapshot'   — restored from a Vercel snapshot (Phase 1+)
 *   'persistent' — reused a named persistent workspace (Phase 2+)
 */
export type SandboxMode = 'fresh' | 'snapshot' | 'persistent'

/**
 * The result of prepareSandboxForTask / resumeSandboxForTask.
 * Wraps the existing SandboxResult with additional provenance metadata.
 *
 * `sandbox` uses Awaited<ReturnType<typeof createSandbox>> so the type stays
 * in sync with createSandbox() without duplicating its shape.
 */
export interface PreparedSandbox {
  /** The underlying SandboxResult from createSandbox() (or future restore path). */
  sandboxResult: Awaited<ReturnType<typeof createSandbox>>
  /** How the sandbox was obtained. With flags off this is always 'fresh'. */
  mode: SandboxMode
  /** Profile fingerprint key, populated in Phase 1+. */
  profileKey?: string
  /** Vercel snapshot id used for restore, populated in Phase 1+. */
  snapshotId?: string
  /** Named workspace identifier, populated in Phase 2+. */
  workspaceName?: string
}

/**
 * Input to prepareSandboxForTask.
 * Mirrors the fields already computed in lib/tasks/process-task.ts before
 * createSandbox() is called, so Phase 1 can drop-in replace without
 * touching process-task.ts.
 */
export interface PrepareSandboxInput {
  taskId: string
  repoUrl: string
  sourceBranch?: string
  installDependencies: boolean
  keepAlive: boolean
  userId: string
  /** Full SandboxConfig to forward to createSandbox() on the fallback path. */
  sandboxConfig: SandboxConfig
  /** TaskLogger instance to pass to createSandbox() on the fallback path. */
  logger: TaskLogger
}

/**
 * Input to resumeSandboxForTask.
 * Extends PrepareSandboxInput with fields needed to locate a persistent
 * workspace (Phase 2+).
 */
export interface ResumeSandboxInput extends PrepareSandboxInput {
  /** Stable repo identifier used to build the workspace name (e.g. 'github.com/owner/repo'). */
  repoId: string
  /** Branch key used in the workspace name (e.g. sanitised branch name). */
  branchKey: string
}

/**
 * Input to stopOrPersistSandbox.
 */
export interface StopSandboxInput {
  taskId: string
  keepAlive: boolean
  userId: string
}
