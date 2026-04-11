#!/usr/bin/env bash
#
# dev-snapshot.sh — Phase 1 placeholder.
#
# Snapshot build/restore is gated behind the SANDBOX_ENABLE_SNAPSHOTS
# feature flag (see lib/sandbox/feature-flags.ts). This script will be
# fleshed out once the flag flips on in Phase 1. Keeping it present
# now so callers can rely on a stable path.
#
set -euo pipefail

echo "dev-snapshot.sh is a Phase 1 placeholder."
echo "Snapshots are gated behind SANDBOX_ENABLE_SNAPSHOTS."
echo "This script will be implemented once the flag is enabled."
exit 0
