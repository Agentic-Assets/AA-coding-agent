# Phase 0 Rollout Checklist

## What Phase 0 Changes at Runtime

Phase 0 upgrades `@vercel/sandbox` from ~0.0.21 to 1.9.3 and introduces a scaffolded sandbox modernization framework with four new tables and optional feature flags. End-user observable change: **none** when all opt-in flags are OFF (default). The SDK upgrade brings Node.js 24 as the default runtime (opt-out via `SANDBOX_USE_NODE24_DEFAULT=0`). New telemetry events appear in server logs as `[sandbox.telemetry]` markers. Three new scaffold tables (`sandbox_profiles`, `sandbox_snapshots`, `sandbox_workspaces`) and four new nullable columns on `tasks` are created but unused during Phase 0.

---

## Pre-Merge Checklist

- [ ] Local `pnpm format:check` passes
- [ ] Local `pnpm type-check` passes
- [ ] Local `pnpm lint` passes
- [ ] Local `pnpm build` succeeds
- [ ] Migrations `0028_steady_puppet_master.sql` and `0029_damp_hellfire_club.sql` reviewed for correctness
- [ ] **Migrations journal note:** The Drizzle migration journal jumps from idx 25 → 28 intentionally. Hand-written migrations `0026_add_sandbox_guardrails.sql` and `0027_add_table_comments_and_fk_indexes.sql` are already deployed to production out-of-band. Do NOT attempt to "fix" the gap.
- [ ] Preview deploy on Vercel: sandbox creation works end-to-end with default flags
- [ ] Test one task via web UI with default env vars; verify it runs and completes
- [ ] Test one task via MCP tool call with Bearer token auth; verify it runs and completes

---

## Deployment Sequence

1. **Merge to `main`** — Vercel auto-deploys; auto-runs migrations in Supabase
2. **Verify migration applied:**
   - [ ] Supabase: Tables `sandbox_profiles`, `sandbox_snapshots`, `sandbox_workspaces` exist
   - [ ] Supabase: Columns `setupProfileKey`, `snapshotId`, `persistentSandboxName`, `snapshotRestoredAt` exist on `tasks` table (all NULL or empty)
3. **Monitor telemetry:**
   - [ ] Server logs contain `[sandbox.telemetry]` events (JSON format)
   - [ ] Baseline `sandbox.create` p50 / p95 latencies logged (Phase 1 will compare)
   - [ ] No spike in `sandbox.create` failure events
4. **Leave feature flags OFF initially** — Phase 1 will toggle them on via environment variables

---

## Environment Variables (Phase 0)

| Flag Name | Phase 0 Value | What Enabling It Does (Phase 1+) |
|-----------|---------------|----------------------------------|
| `SANDBOX_ENABLE_SNAPSHOTS` | `0` (OFF) | Enable snapshot-based sandbox creation; restore from cache instead of fresh clone |
| `SANDBOX_ENABLE_PERSISTENT` | `0` (OFF) | Enable named persistent sandboxes for keep-alive / follow-up sessions (Phase 2+) |
| `SANDBOX_ENABLE_NETWORK_POLICY` | `0` (OFF) | Enable network policy configuration on sandbox creation (Phase 1+) |
| `SANDBOX_USE_NODE24_DEFAULT` | `1` (ON, opt-out) | Use Node.js 24 as default runtime; set to `0` to fall back to Node 22 |

See `lib/sandbox/feature-flags.ts` for implementation.

---

## Rollback Plan

- **If SDK upgrade causes regressions:** Revert entire branch. The new scaffold tables and columns are unused, so revert is safe with no data loss.
- **If Node 24 default causes issues:** Set `SANDBOX_USE_NODE24_DEFAULT=0` in Vercel environment variables. No redeploy required once env var is picked up by the running function.
- **Migrations are additive:** `0028` and `0029` add tables and nullable columns only. Rollback does NOT require dropping tables or columns.
- **Do NOT drop new tables on rollback** — Leave `sandbox_profiles`, `sandbox_snapshots`, `sandbox_workspaces` in place for Phase 1 retry.

---

## Observability Targets

- **`sandbox.create` p50 / p95 latencies** — Baseline for Phase 1 snapshot performance comparison
- **`sandbox.deps.install` p50 / p95** — Key metric Phase 1 optimization will reduce
- **`sandbox.devserver.ready` p50 / p95** — Secondary metric
- **Task success rate** — Must not regress from pre-Phase 0 baseline

See `lib/sandbox/telemetry.ts` for event taxonomy.

---

## Owner & Reference

Phase 0 rollout is documented in:
- **Plan & design:** `docs/VERCEL_SANDBOX_MODERNIZATION_PLAN.md`
- **Feature flags:** `lib/sandbox/feature-flags.ts`
- **Telemetry events:** `lib/sandbox/telemetry.ts`

For questions or escalation, consult the feature branch and the main Modernization Plan.
