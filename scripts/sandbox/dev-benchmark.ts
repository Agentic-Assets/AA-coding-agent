#!/usr/bin/env tsx
/**
 * Vercel Sandbox lifecycle benchmark harness (Phase 0, Task 6).
 *
 * Standalone reference implementation that talks directly to @vercel/sandbox.
 * Deliberately does NOT import from lib/sandbox/* so it stays a clean baseline
 * we can point at when investigating regressions. It is meant to be a
 * reproducible local tool for humans, not production code path.
 *
 * Usage:
 *   pnpm tsx scripts/sandbox/dev-benchmark.ts [options]
 *
 * Options:
 *   --runtime <node22|node24>   Sandbox runtime (default: node24)
 *   --repo <git-url>            Optional public git URL to clone inside the sandbox
 *   --runs <n>                  Number of fresh runs to perform (default: 3)
 *   --install                   Run `npm install` after cloning (default: off)
 *   --help                      Print usage and exit
 *
 * Required env (read at startup, never printed):
 *   SANDBOX_VERCEL_TOKEN
 *   SANDBOX_VERCEL_TEAM_ID
 *   SANDBOX_VERCEL_PROJECT_ID
 *
 * Logging contract:
 *   All console.* calls use string literals as the first argument. Any
 *   dynamic data is passed as a second argument (structured), so this script
 *   conforms to the repo-wide static-logging rule even though it is a local
 *   developer tool.
 */

import { Sandbox } from '@vercel/sandbox'
import { performance } from 'node:perf_hooks'

type RuntimeName = 'node22' | 'node24'

interface BenchmarkOptions {
  runtime: RuntimeName
  repo: string | null
  runs: number
  install: boolean
}

type PhaseName = 'create' | 'clone' | 'install' | 'total'

interface RunRecord {
  run: number
  create: number | null
  clone: number | null
  install: number | null
  total: number | null
  error: string | null
}

const HELP = `Vercel Sandbox dev benchmark harness

Usage:
  pnpm tsx scripts/sandbox/dev-benchmark.ts [options]

Options:
  --runtime <node22|node24>   Sandbox runtime (default: node24)
  --repo <git-url>            Optional public git URL to clone inside the sandbox
  --runs <n>                  Number of fresh runs to perform (default: 3)
  --install                   Run npm install after cloning (default: off)
  --help                      Print this help and exit
`

function parseArgs(argv: readonly string[]): BenchmarkOptions | { help: true } {
  const opts: BenchmarkOptions = {
    runtime: 'node24',
    repo: null,
    runs: 3,
    install: false,
  }

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    switch (arg) {
      case '--help':
      case '-h':
        return { help: true }
      case '--runtime': {
        const value = argv[++i]
        if (value !== 'node22' && value !== 'node24') {
          throw new Error('Invalid --runtime value; expected node22 or node24')
        }
        opts.runtime = value
        break
      }
      case '--repo': {
        const value = argv[++i]
        if (!value) throw new Error('Missing value for --repo')
        opts.repo = value
        break
      }
      case '--runs': {
        const value = argv[++i]
        const parsed = Number.parseInt(value ?? '', 10)
        if (!Number.isFinite(parsed) || parsed < 1) {
          throw new Error('Invalid --runs value; expected positive integer')
        }
        opts.runs = parsed
        break
      }
      case '--install':
        opts.install = true
        break
      default:
        throw new Error('Unknown argument encountered')
    }
  }

  return opts
}

function requireEnv(): { token: string; teamId: string; projectId: string } {
  const token = process.env.SANDBOX_VERCEL_TOKEN
  const teamId = process.env.SANDBOX_VERCEL_TEAM_ID
  const projectId = process.env.SANDBOX_VERCEL_PROJECT_ID

  const missing: string[] = []
  if (!token) missing.push('SANDBOX_VERCEL_TOKEN')
  if (!teamId) missing.push('SANDBOX_VERCEL_TEAM_ID')
  if (!projectId) missing.push('SANDBOX_VERCEL_PROJECT_ID')

  if (missing.length > 0 || !token || !teamId || !projectId) {
    // Static first arg; the array of names is safe (no values).
    console.error('Missing required environment variables', { missing })
    process.exit(1)
  }

  return { token, teamId, projectId }
}

function classifyError(err: unknown): string {
  if (err instanceof Error) return err.name || 'Error'
  return 'unknown'
}

async function measure<T>(fn: () => Promise<T>): Promise<{ result: T; ms: number }> {
  const start = performance.now()
  const result = await fn()
  const ms = performance.now() - start
  return { result, ms }
}

function percentile(values: number[], p: number): number | null {
  if (values.length === 0) return null
  const sorted = [...values].sort((a, b) => a - b)
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))
  return sorted[idx]
}

function mean(values: number[]): number | null {
  if (values.length === 0) return null
  return values.reduce((a, b) => a + b, 0) / values.length
}

function fmtMs(value: number | null): string {
  if (value === null) return '—'
  return `${value.toFixed(0)}ms`
}

async function runOnce(
  options: BenchmarkOptions,
  credentials: { token: string; teamId: string; projectId: string },
  runIndex: number,
): Promise<RunRecord> {
  const record: RunRecord = {
    run: runIndex + 1,
    create: null,
    clone: null,
    install: null,
    total: null,
    error: null,
  }

  const totalStart = performance.now()
  let sandbox: Sandbox | null = null

  try {
    console.log('Run starting', { run: record.run, runtime: options.runtime })

    // Phase: create
    const createResult = await measure(() =>
      Sandbox.create({
        token: credentials.token,
        teamId: credentials.teamId,
        projectId: credentials.projectId,
        runtime: options.runtime,
        // 30 min ceiling is plenty for a benchmark; clone+install rarely exceed a few minutes.
        timeout: 30 * 60 * 1000,
      }),
    )
    sandbox = createResult.result
    record.create = createResult.ms
    console.log('Phase complete', { phase: 'create', ms: Math.round(record.create) })

    // Phase: clone (optional)
    if (options.repo) {
      const cloneResult = await measure(async () => {
        if (!sandbox) throw new Error('Sandbox not created')
        return sandbox.runCommand('git', ['clone', '--depth', '1', options.repo as string, 'project'])
      })
      record.clone = cloneResult.ms
      console.log('Phase complete', { phase: 'clone', ms: Math.round(record.clone) })
    }

    // Phase: install (optional, requires a cloned repo with package.json)
    if (options.install && options.repo) {
      const installResult = await measure(async () => {
        if (!sandbox) throw new Error('Sandbox not created')
        return sandbox.runCommand('sh', ['-c', 'cd project && npm install --no-audit --no-fund'])
      })
      record.install = installResult.ms
      console.log('Phase complete', { phase: 'install', ms: Math.round(record.install) })
    }

    record.total = performance.now() - totalStart
    console.log('Run finished', { run: record.run, totalMs: Math.round(record.total) })
  } catch (err) {
    record.error = classifyError(err)
    record.total = performance.now() - totalStart
    // Static first arg; second arg carries only the error class, not the message.
    console.error('Run failed', { run: record.run, errorClass: record.error })
  } finally {
    if (sandbox) {
      try {
        await sandbox.stop()
        console.log('Sandbox stopped', { run: record.run })
      } catch {
        console.error('Sandbox stop failed', { run: record.run })
      }
    }
  }

  return record
}

function printSummary(runs: RunRecord[]): void {
  console.log('Benchmark summary')

  // Per-run table
  console.log('Per-run timings (ms)')
  for (const r of runs) {
    console.log('Row', {
      run: r.run,
      create: fmtMs(r.create),
      clone: fmtMs(r.clone),
      install: fmtMs(r.install),
      total: fmtMs(r.total),
      error: r.error ?? 'none',
    })
  }

  // Aggregates per phase
  const phases: PhaseName[] = ['create', 'clone', 'install', 'total']
  console.log('Aggregates per phase (ms)')
  for (const phase of phases) {
    const values = runs.map((r) => r[phase]).filter((v): v is number => typeof v === 'number')
    if (values.length === 0) {
      console.log('Aggregate', { phase, n: 0 })
      continue
    }
    console.log('Aggregate', {
      phase,
      n: values.length,
      mean: fmtMs(mean(values)),
      p50: fmtMs(percentile(values, 50)),
      p95: fmtMs(percentile(values, 95)),
    })
  }
}

async function main(): Promise<void> {
  let parsed: BenchmarkOptions | { help: true }
  try {
    parsed = parseArgs(process.argv.slice(2))
  } catch (err) {
    console.error('Argument parsing failed', { errorClass: classifyError(err) })
    console.log(HELP)
    process.exit(1)
  }

  if ('help' in parsed) {
    console.log(HELP)
    process.exit(0)
  }

  const options = parsed
  const credentials = requireEnv()

  console.log('Benchmark configuration', {
    runtime: options.runtime,
    runs: options.runs,
    hasRepo: options.repo !== null,
    install: options.install,
  })

  const results: RunRecord[] = []
  let anyFailure = false

  for (let i = 0; i < options.runs; i++) {
    const record = await runOnce(options, credentials, i)
    results.push(record)
    if (record.error) anyFailure = true
  }

  printSummary(results)

  if (anyFailure) {
    console.error('One or more runs failed')
    process.exit(2)
  }
}

main().catch((err) => {
  // Static first arg; only the error class is structured-logged.
  console.error('Benchmark crashed', { errorClass: classifyError(err) })
  process.exit(1)
})
