#!/usr/bin/env bash
#
# dev-create.sh — human smoke test for Vercel Sandbox creation.
#
# Spins up an ephemeral sandbox via the Vercel CLI so you can confirm
# your SANDBOX_VERCEL_* credentials and network path are healthy without
# running a full task through the app. This is a debug helper, not a
# production code path.
#
# Prerequisites:
#   - Vercel CLI installed (npm i -g vercel) and `vercel login` completed,
#     OR SANDBOX_VERCEL_TOKEN / SANDBOX_VERCEL_TEAM_ID / SANDBOX_VERCEL_PROJECT_ID
#     exported in your shell.
#
# Usage:
#   scripts/sandbox/dev-create.sh [extra vercel sandbox args...]
#
# Example:
#   scripts/sandbox/dev-create.sh --runtime node24
#
set -euo pipefail

if ! command -v vercel >/dev/null 2>&1; then
  echo "vercel CLI not found on PATH. Install with: npm i -g vercel" >&2
  exit 1
fi

# Forward any extra args to the underlying command so callers can pass
# --runtime, --timeout, etc. without editing this script.
exec vercel sandbox "$@"
