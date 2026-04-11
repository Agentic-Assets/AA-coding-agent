# scripts/sandbox

Reproducible developer helpers for the Vercel Sandbox modernization work.
These are local debugging tools; they are not imported by the app and do
not ship as part of a production code path.

All scripts respect the repo-wide static-logging rule: they never print
credentials, branch names, user IDs, or other sensitive dynamic values.
Token presence is checked via env var names only.

## Scripts

| Script              | Phase | Purpose                                                                 |
| ------------------- | ----- | ----------------------------------------------------------------------- |
| `dev-benchmark.ts`  | 0     | Programmatic lifecycle benchmark against `@vercel/sandbox` (SDK direct) |
| `dev-benchmark.sh`  | 0     | Thin wrapper for `pnpm tsx scripts/sandbox/dev-benchmark.ts`            |
| `dev-create.sh`     | 0     | Human smoke test using `vercel sandbox` CLI                             |
| `dev-snapshot.sh`   | 1     | Placeholder — gated behind `SANDBOX_ENABLE_SNAPSHOTS`                   |
| `dev-restore.sh`    | 1     | Placeholder — gated behind `SANDBOX_ENABLE_SNAPSHOTS`                   |
| `dev-persistent.sh` | 2     | Placeholder — gated behind `SANDBOX_ENABLE_PERSISTENT`                  |

## Required environment

All scripts that hit the Vercel API read credentials from:

- `SANDBOX_VERCEL_TOKEN`
- `SANDBOX_VERCEL_TEAM_ID`
- `SANDBOX_VERCEL_PROJECT_ID`

Missing variables fail fast with a static error message before any SDK
call is made.

## Examples

```bash
# One fresh run with node24, no clone.
pnpm tsx scripts/sandbox/dev-benchmark.ts

# Three runs, clone a public repo, install deps, node24 runtime.
scripts/sandbox/dev-benchmark.sh \
  --runtime node24 \
  --runs 3 \
  --repo https://github.com/vercel/next.js \
  --install

# Quick CLI-level smoke test.
scripts/sandbox/dev-create.sh --runtime node24
```

The benchmark prints per-run timings plus mean / p50 / p95 per phase to
stdout. Use it as the baseline when investigating regressions in
`lib/sandbox/creation.ts`.
