#!/usr/bin/env bash
#
# dev-benchmark.sh — thin wrapper around the TypeScript benchmark harness.
#
# Forwards all arguments to `pnpm tsx scripts/sandbox/dev-benchmark.ts`.
# The TS script reads SANDBOX_VERCEL_TOKEN / SANDBOX_VERCEL_TEAM_ID /
# SANDBOX_VERCEL_PROJECT_ID from the environment and never prints them.
#
# Usage:
#   scripts/sandbox/dev-benchmark.sh --runtime node24 --runs 3
#   scripts/sandbox/dev-benchmark.sh --repo https://github.com/vercel/next.js --install
#
set -euo pipefail

# Resolve repo root relative to this script so the wrapper works from any cwd.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$REPO_ROOT"
exec pnpm tsx scripts/sandbox/dev-benchmark.ts "$@"
