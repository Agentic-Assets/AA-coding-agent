# CLAUDE.md

Canonical agent guide for this repo. Root **`AGENTS.md`** is a one-line `@CLAUDE.md` pointer so tools that only read `AGENTS.md` still land here.

**Next.js (read before coding):** Open the matching topic under `./.next-docs` (full index at the end of this file). If absent, run `npx @next/codemod agents-md --output CLAUDE.md`. You may also use `node_modules/next/dist/docs/` when present. Training data is not authoritative.

## Project overview

Multi-agent AI coding assistant: Next.js 16, React 19, Drizzle/Supabase, Vercel Sandboxes, OAuth (GitHub/Vercel), tasks, MCP connectors, GitHub integration. Agents: Claude, Codex, Copilot, Cursor, Gemini, OpenCode.

## Core architecture

- **Stack**: App Router, Tailwind v4, shadcn/ui, Streamdown; API routes; Vercel AI SDK 5; Sandbox v0.0.21 (~300 min default); JWE sessions; MCP (mcp-handler).
- **Dirs**: `app/`, `lib/`, `lib/sandbox/`, `lib/sandbox/agents/`, `lib/db/`, `lib/auth/`, `components/`, `scripts/`.
- **Schema (`lib/db/schema.ts`)**: users, accounts, keys, apiTokens, tasks (`logs`, `branchName`, `sourceBranch`, `subAgentActivity`, `currentSubAgent`, `lastHeartbeat`), taskMessages, connectors, settings.

## Development workflow

**Setup (drizzle-kit needs `.env`):**
```bash
pnpm install
cp .env.local .env
DOTENV_CONFIG_PATH=.env pnpm tsx -r dotenv/config node_modules/drizzle-kit/bin.cjs migrate
rm .env
```

**Commands:** `pnpm build` to verify (do **not** run `pnpm dev` / `next dev` / long-lived servers—they block the session and fight for ports). `pnpm db:generate` | `db:push` | `db:studio`. Quality: `pnpm format`, `pnpm format:check`, `pnpm type-check`, `pnpm lint`—run after TS/TSX edits and fix all issues.

**Deploy:** `pnpm build` → commit/push → Vercel; optional `vercel inspect <url> --wait`.

`POSTGRES_URL` in `.env.local` for local DB; see README for full env setup.

## Security & logging (critical)

**User-visible logs (`logger.*`, UI-facing `console.*`): static strings only—no template literals with `${...}`.** Applies to every level (info, error, success, command).

**Never log (even “sanitized”):** user IDs/emails, paths, repo URLs, **branch names**, commit SHAs/messages, raw `Error` text to TaskLogger, Bearer tokens / `/api/tokens` secrets, `SANDBOX_VERCEL_*`, provider keys, `JWE_SECRET`, `ENCRYPTION_KEY`, GitHub token prefixes (`ghp_`, etc.).

**`redactSensitiveInfo()`** (`lib/utils/logging.ts`): best-effort redaction (keys, gh tokens, Vercel trio, Bearer, JSON `teamId`/`projectId`, env-like `*KEY*`, `*SECRET*`, etc.)—**backup only**; do not log dynamics and rely on redaction.

**Pattern:** TaskLogger/user messages = generic static line; server-only `console.error` for engineering debug is ok if it does not print secrets.

**After editing logging:** search your changes for template literals in `logger`/`console` calls.

## Task creation (API & MCP)

Fields: `prompt`, `repoUrl`, `selectedAgent` (default `claude`), `selectedModel`, `sourceBranch` (optional), `installDependencies` (default false), `maxDuration` (minutes, default 300), `keepAlive` (default false).

**Branches:** `GET /api/github/branches?owner=&repo=` returns `{ branches[], defaultBranch }`. Clone uses `--branch` when set; missing branch → repo default. **Do not log branch names** in user-facing logs.

## AI agent system

**Implementations** (`lib/sandbox/agents/*.ts`): `runAgent()`, TaskLogger, sandbox commands, git push, model + keys (user DB keys override env).

### Claude: Anthropic vs AI Gateway
- **Claude models** (`claude-sonnet-4-5-20250929`, `claude-opus-4-5-20251101`, …): `ANTHROPIC_API_KEY`; config `~/.config/claude/config.json`.
- **Gateway models** (e.g. Gemini / OpenAI / Z.ai via gateway): prefer `AI_GATEWAY_API_KEY`. In sandbox set `ANTHROPIC_BASE_URL=https://ai-gateway.vercel.sh`, `ANTHROPIC_AUTH_TOKEN=<gateway key>`, `ANTHROPIC_API_KEY=""` so the SDK hits the gateway.
- Code priority (`claude.ts`): gateway key first, then Anthropic; error if neither. UI (`components/task-form.tsx`):

```typescript
const getClaudeRequiredKeys = (model: string): Provider[] =>
  model.startsWith('claude-') ? ['anthropic'] : ['aigateway']
```

### Task pipeline (`lib/tasks/process-task.ts` → `processTaskWithTimeout`)
Validate → sandbox → clone (`sourceBranch` or default) → env (keys, npm, MCP) → agent → feature branch / commit / push → shutdown unless `keepAlive`. Same path for REST and MCP.

### Sub-agents & timeout
`TaskLogger`: `startSubAgent`, `subAgentRunning`, `completeSubAgent`, `heartbeat`. State in `tasks.subAgentActivity` (see `subAgentActivitySchema`). Logs update `lastHeartbeat`; active sub-agents + recent heartbeat can extend deadline (base + grace, polled ~30s). UI: `SubAgentIndicator`.

### MCP in sandbox
- **Claude**: `.mcp.json` — local CLI + remote HTTP, encrypted env/OAuth; works with Anthropic or gateway auth.
- **Codex**: `~/.codex/config.toml` — stdio, experimental remote, bearer.
- **Copilot**: `.copilot/mcp-config.json` — stdio + HTTP, optional `tools` list.
- **Cursor, Gemini, OpenCode**: no MCP.

### Agent matrix (keys, streaming, resume, install)

| Agent | Auth / keys | Default model | Streams | Resume | Install |
|-------|-------------|----------------|---------|--------|---------|
| Claude | AI_GATEWAY → ANTHROPIC | `claude-sonnet-4-5-20250929` | Yes (NDJSON → taskMessages) | `--resume "<uuid>"` or `--continue` | Claude Code (preinstalled in typical env) |
| Codex | `AI_GATEWAY_API_KEY` (`sk-` or `vck_`) | `openai/gpt-4o` | No (batch) | `--last` only | `npm i -g @openai/codex` |
| Copilot | `GH_TOKEN` / `GITHUB_TOKEN` | optional | Yes (text) | `--resume` (unreliable) | `npm i -g @github/copilot` |
| Cursor | `CURSOR_API_KEY` | — | Yes | session id | Official curl installer → `~/.local/bin/cursor-agent` |
| Gemini | `GEMINI_API_KEY` | n/a (param ignored) | No | none | `npm i -g @google/gemini-cli` |
| OpenCode | `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` | none | No | none | npm global (implied) |

## Delegating to specialized subagents (Claude Code)

Prefer `.claude/agents/` specialists for focused work: **api-route-architect**, **database-schema-optimizer**, **sandbox-agent-manager**, **security-logging-enforcer**, **security-expert**, **senior-code-reviewer**, **react-component-builder**, **react-expert**, **shadcn-ui-expert**, **tailwind-expert**, **ui-engineer**, **supabase-expert**, **docs-maintainer**, **agent-expert**, **research-search-expert**. Use built-in/plugin agents when they fit.

## API architecture

**Auth:** OAuth → `users` + encrypted token → JWE cookie (`lib/session/create.ts`) → `getServerSession()` (`lib/session/get-server-session.ts`); extra identities in `accounts`.

**GitHub HTTP:** `GET /api/github/user`, `user-repos`, `repos`, `POST repos/create`, `verify-repo`, `orgs`, `branches` (query `owner`, `repo` → `{ branches[], defaultBranch }`). **Repo tabs API:** `app/api/repos/[owner]/[repo]/` → `commits`, `issues`, `pull-requests`.

**Other:** `app/api/auth/*`, `tasks/*`, `connectors/*`, `api-keys/*`, `sandboxes/*`, `tokens/*` (Bearer or `?apikey=` for MCP).

### API tokens (Bearer / `?apikey=`)

Settings UI or `POST /api/tokens` → raw token once → SHA256 at rest. `GET/DELETE /api/tokens`. Same `userId` as session for GitHub + stored keys. Endpoints: `/api/tasks/*`, `/api/tokens/*`, `/api/mcp`. Max 20/user (rate limited).

**Dual auth** (`lib/auth/api-token.ts`):
```typescript
import { getAuthFromRequest } from '@/lib/auth/api-token'

// Checks Bearer token first, falls back to session cookie
const user = await getAuthFromRequest(request)
```

Use `getAuthFromRequest()` for routes that should accept both Bearer tokens and session cookies.

### Rate Limiting
Default: 20 tasks + follow-ups per user per day (configurable via `MAX_MESSAGES_PER_DAY` env var). Admin domains in `NEXT_PUBLIC_ADMIN_EMAIL_DOMAINS` get 100/day. See `lib/utils/rate-limit.ts`.

## UI Component Guidelines

### Using shadcn/ui Components
**Always check if a shadcn component exists before creating new UI components:**
```bash
pnpm dlx shadcn@latest add <component-name>
```
Existing components in `components/ui/`. See https://ui.shadcn.com/ for available components.

### Repository pages

Layout + tabs: `components/repo-layout.tsx`; tab bodies `repo-commits.tsx`, `repo-issues.tsx`, `repo-pull-requests.tsx`. Routes:

```
app/repos/[owner]/[repo]/layout.tsx, page.tsx → commits
commits/page.tsx, issues/page.tsx, pull-requests/page.tsx
```

**Add a tab:**
1. Create `app/repos/[owner]/[repo]/[tab-name]/page.tsx`
2. Create component in `components/repo-[tab-name].tsx`
3. Add API route in `app/api/repos/[owner]/[repo]/[tab-name]/route.ts`
4. Update `tabs` array in `components/repo-layout.tsx`

## Environment variables

Store secrets in **`.env.local`** (not committed `.env`). Drizzle migrate workaround: copy to `.env` temporarily (see Development workflow).

**Never log or send to the client:** `SANDBOX_VERCEL_*`, provider keys (`ANTHROPIC_*`, `AI_GATEWAY_*`, `OPENAI_*`, `GEMINI_*`, `CURSOR_*`), `GH_TOKEN`/`GITHUB_TOKEN`, `JWE_SECRET`, `ENCRYPTION_KEY`, user-stored keys, raw API tokens.

**Safe to expose via `NEXT_PUBLIC_*`:** e.g. `NEXT_PUBLIC_AUTH_PROVIDERS`, `NEXT_PUBLIC_GITHUB_CLIENT_ID`, `NEXT_PUBLIC_VERCEL_CLIENT_ID` (OAuth client ids only).

### Required (app infrastructure)
- `POSTGRES_URL` - Supabase PostgreSQL connection string (from Supabase project settings)
- `SANDBOX_VERCEL_TOKEN` - Vercel API token for sandbox creation
- `SANDBOX_VERCEL_TEAM_ID` - Vercel team ID
- `SANDBOX_VERCEL_PROJECT_ID` - Vercel project ID
- `JWE_SECRET` - Session encryption secret (generate: `openssl rand -base64 32`)
- `ENCRYPTION_KEY` - API key/token encryption (generate: `openssl rand -hex 32`)

### Authentication (At Least One Required)
- `NEXT_PUBLIC_AUTH_PROVIDERS` - Comma-separated: "github", "vercel", or "github,vercel"
- **GitHub**: `NEXT_PUBLIC_GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`
- **Vercel**: `NEXT_PUBLIC_VERCEL_CLIENT_ID`, `VERCEL_CLIENT_SECRET`

### Optional (Global Fallbacks - Users Can Override)
- `ANTHROPIC_API_KEY` - Claude agent with Anthropic models (claude-*)
- `AI_GATEWAY_API_KEY` - Claude agent with alternative models + branch name generation + Codex
- `OPENAI_API_KEY` - Codex/OpenCode agents
- `CURSOR_API_KEY` - Cursor agent
- `GEMINI_API_KEY` - Gemini agent
- `NPM_TOKEN` - Private npm packages
- `MAX_SANDBOX_DURATION` - Default max duration in minutes (default: 300)
- `MAX_MESSAGES_PER_DAY` - Rate limit (default: 20)
- `NEXT_PUBLIC_ADMIN_EMAIL_DOMAINS` - Admin email domains for 100/day limit

## Key Implementation Patterns

### User-Scoped Data Access
All database queries filter by `userId`. Users can only access their own tasks, connectors, API keys:
```typescript
const tasks = await db.query.tasks.findMany({
  where: eq(tasks.userId, user.id),
})
```

### Encryption & decryption
`lib/crypto.ts`: `encrypt(plaintext)` for storage; **`decrypt` returns `string | null`**—**never throw**; fall back (e.g. env) or skip on null.

**Sessions (`lib/jwe/decrypt.ts`):** **`decryptJWE<T>()` returns `T | undefined`** if invalid/expired—treat as logged out; do not throw.

### User-stored API keys (priority: user → env, never mix)
```typescript
import { decrypt } from '@/lib/crypto'
import { getUserApiKey } from '@/lib/api-keys/user-keys'

const decrypted = decrypt(userKey.value)
if (decrypted === null) return systemKey
return decrypted
```
Log only static messages (e.g. `'Error fetching user API key'`)—never values or `Error` text to TaskLogger.

**Shortcut:** `const k = await getUserApiKey(userId, 'anthropic') || process.env.ANTHROPIC_API_KEY`

### API Token Authentication Support
Functions now accept optional `userId` parameter for external API token authentication (bypasses session lookup):
```typescript
// Works with session cookie (no userId)
const token = await getUserGitHubToken()

// Works with API token auth (explicit userId)
const token = await getUserGitHubToken(userId)

// Same pattern for other functions
const apiKeys = await getUserApiKeys(userId)
const user = await getGitHubUser(userId)
```

This pattern enables MCP tools and external clients to work with full user context using API tokens.

### Shared Task Processing Module
Central task processing logic at `lib/tasks/process-task.ts` handles both REST API and MCP execution:
- `processTaskWithTimeout(input)` - Main task execution with timeout wrapper
- `generateTaskBranchName()` - Non-blocking AI-generated branch names
- `generateTaskTitleAsync()` - Non-blocking AI-generated task titles
- Accepts `TaskProcessingInput` with githubToken and githubUser for authenticated execution

### Task Logging with TaskLogger
Use `lib/utils/task-logger.ts` for structured, real-time task logs with agent context tracking:
```typescript
const logger = new TaskLogger(taskId)
await logger.info('Operation started')
await logger.updateProgress(50, 'Processing')
await logger.success('Completed')
await logger.error('Failed')

// Sub-agent tracking
const subAgentId = await logger.startSubAgent('Explore', 'Exploring repository')
await logger.subAgentRunning(subAgentId)
await logger.completeSubAgent(subAgentId, true)

// Send heartbeat to extend timeout during long operations
await logger.heartbeat()

// Create logger with agent context
const contextLogger = logger.withAgentContext({ name: 'claude', isSubAgent: false })
await contextLogger.info('Logged with Claude agent context')
```

All log operations automatically update `lastHeartbeat` for timeout extension.

### AI Branch Name Generation
Uses Vercel AI SDK 5 + AI Gateway in `lib/utils/branch-name-generator.ts`:
- Non-blocking (Next.js `after()` function)
- Descriptive names like `feature/user-auth-A1b2C3` or `fix/memory-leak-X9y8Z7`
- Fallback to timestamp-based names on failure
- Includes 6-character hash to prevent conflicts

## Common Development Tasks

### Adding a New AI Agent
1. Create `lib/sandbox/agents/new-agent.ts` implementing `runAgent()` function
2. Add agent to `selectedAgent` enum in `lib/db/schema.ts` (tasks table)
3. Add to agent selection UI in `components/task-form.tsx`
4. Add API key support in `keys` table schema if needed
5. Update agent index in `lib/sandbox/agents/index.ts`

### Database Schema Changes
1. Edit `lib/db/schema.ts`
2. Generate migration: `pnpm db:generate`
3. Apply to local DB (requires workaround):
   ```bash
   cp .env.local .env
   DOTENV_CONFIG_PATH=.env pnpm tsx -r dotenv/config node_modules/drizzle-kit/bin.cjs migrate
   rm .env
   ```
4. Test changes locally
5. Deploy: Push to Git (migrations auto-run on Vercel)

### Adding New API Routes
1. Create route file in `app/api/[path]/route.ts`
2. Import session validation: `import { getServerSession } from '@/lib/session/get-server-session'`
3. Validate user: `const user = await getServerSession()`
4. Filter queries by `userId`
5. Use static log messages (no dynamic values)

## Testing & verification

Before merge/deploy: `pnpm format`, `pnpm format:check`, `pnpm type-check`, `pnpm lint`, `pnpm build`. Logs: static strings only; spot-check template literals in `logger`/`console` you changed; UI logs show no secrets. Queries scoped by `userId`; tokens/keys encrypted.

## Breaking changes (v2.0)
- All tables now require `userId` foreign key
- API routes require authentication
- `GITHUB_TOKEN` no longer used as fallback (users provide their own)
- Connector `env` changed from jsonb to encrypted text
- See README.md "Changelog" section for full migration guide

## Additional resources

- **AI_MODELS_AND_KEYS.md** - API keys and models
- **README.md** - Full setup instructions, OAuth configuration, deployment guide
- **Vercel Sandbox Docs** - https://vercel.com/docs/vercel-sandbox
- **Vercel AI SDK 5** - https://sdk.vercel.ai/docs
- **Vercel AI Gateway** - https://vercel.com/docs/ai-gateway
- **Drizzle ORM** - https://orm.drizzle.team/docs/overview
- **shadcn/ui** - https://ui.shadcn.com/

## MCP server (HTTP)

**`/api/mcp`** — Streamable HTTP (POST/GET/DELETE), no SSE. Auth: `Authorization: Bearer <token>` or `?apikey=` (HTTPS only; tokens hashed at rest). Same rate limits as web UI; tools user-scoped.

**Tools:** `create-task` (runs full `processTaskWithTimeout`, needs GitHub linked, optional `sourceBranch`) → `taskId`, `status`, `createdAt`; `get-task`; `continue-task`; `list-tasks`; `stop-task`. Token auth supplies `userId` for GitHub + stored API keys like session auth.

**Claude Desktop example** (`~/Library/Application Support/Claude/claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "aa-coding-agent": {
      "url": "https://your-domain.com/api/mcp?apikey=YOUR_API_TOKEN"
    }
  }
}
```

**Code:** `app/api/mcp/route.ts`, `lib/mcp/tools/`, `lib/mcp/schemas.ts`, `mcp-handler`; task execution `lib/tasks/process-task.ts`. Details: `docs/MCP_SERVER.md`.

## Recent improvements (2026-01-26)

Static-only logging hardening (migrate-production, vercel-client user, claude agent, GitHub OAuth callback). DB: migration `0025_add_rate_limit_indexes.sql` for task/message rate-limit queries. Frontend: `optimizePackageImports` (lucide, radix icons), dynamic Monaco in `file-editor`, parallel fetches in `app/api/tasks/route.ts`.

## Important Reminders

1. **Never log dynamic values** - Use static strings in all logger/console statements
2. **Always run code quality checks** - format, type-check, lint after editing TS/TSX
3. **Never run dev servers** - Use build verification or let user start servers
4. **Cloud-first deployment** - Push to Git, let Vercel handle builds
5. **User-scoped access** - Filter all queries by userId
6. **Encrypt sensitive data** - Use lib/crypto.ts for tokens and API keys
7. **Check for existing components** - Use shadcn CLI before creating new UI components
8. **Claude API Gateway support** - Use AI_GATEWAY_API_KEY for alternative models, ANTHROPIC_API_KEY for Claude models

<!-- NEXT-AGENTS-MD-START -->[Next.js Docs Index]|root: ./.next-docs|STOP. What you remember about Next.js is WRONG for this project. Always search docs and read before any task.|If docs missing, run this command first: npx @next/codemod agents-md --output CLAUDE.md|01-app:{04-glossary.mdx}|01-app/01-getting-started:{01-installation.mdx,02-project-structure.mdx,03-layouts-and-pages.mdx,04-linking-and-navigating.mdx,05-server-and-client-components.mdx,06-fetching-data.mdx,07-mutating-data.mdx,08-caching.mdx,09-revalidating.mdx,10-error-handling.mdx,11-css.mdx,12-images.mdx,13-fonts.mdx,14-metadata-and-og-images.mdx,15-route-handlers.mdx,16-proxy.mdx,17-deploying.mdx,18-upgrading.mdx}|01-app/02-guides:{ai-agents.mdx,analytics.mdx,authentication.mdx,backend-for-frontend.mdx,caching-without-cache-components.mdx,cdn-caching.mdx,ci-build-caching.mdx,content-security-policy.mdx,css-in-js.mdx,custom-server.mdx,data-security.mdx,debugging.mdx,deploying-to-platforms.mdx,draft-mode.mdx,environment-variables.mdx,forms.mdx,how-revalidation-works.mdx,incremental-static-regeneration.mdx,instant-navigation.mdx,instrumentation.mdx,internationalization.mdx,json-ld.mdx,lazy-loading.mdx,local-development.mdx,mcp.mdx,mdx.mdx,memory-usage.mdx,migrating-to-cache-components.mdx,multi-tenant.mdx,multi-zones.mdx,open-telemetry.mdx,package-bundling.mdx,ppr-platform-guide.mdx,prefetching.mdx,preserving-ui-state.mdx,production-checklist.mdx,progressive-web-apps.mdx,public-static-pages.mdx,redirecting.mdx,rendering-philosophy.mdx,sass.mdx,scripts.mdx,self-hosting.mdx,single-page-applications.mdx,static-exports.mdx,streaming.mdx,tailwind-v3-css.mdx,third-party-libraries.mdx,videos.mdx,view-transitions.mdx}|01-app/02-guides/migrating:{app-router-migration.mdx,from-create-react-app.mdx,from-vite.mdx}|01-app/02-guides/testing:{cypress.mdx,jest.mdx,playwright.mdx,vitest.mdx}|01-app/02-guides/upgrading:{codemods.mdx,version-14.mdx,version-15.mdx,version-16.mdx}|01-app/03-api-reference:{07-edge.mdx,08-turbopack.mdx}|01-app/03-api-reference/01-directives:{use-cache-private.mdx,use-cache-remote.mdx,use-cache.mdx,use-client.mdx,use-server.mdx}|01-app/03-api-reference/02-components:{font.mdx,form.mdx,image.mdx,link.mdx,script.mdx}|01-app/03-api-reference/03-file-conventions/01-metadata:{app-icons.mdx,manifest.mdx,opengraph-image.mdx,robots.mdx,sitemap.mdx}|01-app/03-api-reference/03-file-conventions/02-route-segment-config:{dynamicParams.mdx,instant.mdx,maxDuration.mdx,preferredRegion.mdx,runtime.mdx}|01-app/03-api-reference/03-file-conventions:{default.mdx,dynamic-routes.mdx,error.mdx,forbidden.mdx,instrumentation-client.mdx,instrumentation.mdx,intercepting-routes.mdx,layout.mdx,loading.mdx,mdx-components.mdx,not-found.mdx,page.mdx,parallel-routes.mdx,proxy.mdx,public-folder.mdx,route-groups.mdx,route.mdx,src-folder.mdx,template.mdx,unauthorized.mdx}|01-app/03-api-reference/04-functions:{after.mdx,cacheLife.mdx,cacheTag.mdx,catchError.mdx,connection.mdx,cookies.mdx,draft-mode.mdx,fetch.mdx,forbidden.mdx,generate-image-metadata.mdx,generate-metadata.mdx,generate-sitemaps.mdx,generate-static-params.mdx,generate-viewport.mdx,headers.mdx,image-response.mdx,next-request.mdx,next-response.mdx,not-found.mdx,permanentRedirect.mdx,redirect.mdx,refresh.mdx,revalidatePath.mdx,revalidateTag.mdx,unauthorized.mdx,unstable_cache.mdx,unstable_noStore.mdx,unstable_rethrow.mdx,updateTag.mdx,use-link-status.mdx,use-params.mdx,use-pathname.mdx,use-report-web-vitals.mdx,use-router.mdx,use-search-params.mdx,use-selected-layout-segment.mdx,use-selected-layout-segments.mdx,userAgent.mdx}|01-app/03-api-reference/05-config/01-next-config-js:{adapterPath.mdx,allowedDevOrigins.mdx,appDir.mdx,assetPrefix.mdx,authInterrupts.mdx,basePath.mdx,cacheComponents.mdx,cacheHandlers.mdx,cacheLife.mdx,compress.mdx,crossOrigin.mdx,cssChunking.mdx,deploymentId.mdx,devIndicators.mdx,distDir.mdx,env.mdx,expireTime.mdx,exportPathMap.mdx,generateBuildId.mdx,generateEtags.mdx,headers.mdx,htmlLimitedBots.mdx,httpAgentOptions.mdx,images.mdx,incrementalCacheHandlerPath.mdx,inlineCss.mdx,logging.mdx,mdxRs.mdx,onDemandEntries.mdx,optimizePackageImports.mdx,output.mdx,pageExtensions.mdx,poweredByHeader.mdx,productionBrowserSourceMaps.mdx,proxyClientMaxBodySize.mdx,reactCompiler.mdx,reactMaxHeadersLength.mdx,reactStrictMode.mdx,redirects.mdx,rewrites.mdx,sassOptions.mdx,serverActions.mdx,serverComponentsHmrCache.mdx,serverExternalPackages.mdx,staleTimes.mdx,staticGeneration.mdx,taint.mdx,trailingSlash.mdx,transpilePackages.mdx,turbopack.mdx,turbopackFileSystemCache.mdx,turbopackIgnoreIssue.mdx,typedRoutes.mdx,typescript.mdx,urlImports.mdx,useLightningcss.mdx,viewTransition.mdx,webVitalsAttribution.mdx,webpack.mdx}|01-app/03-api-reference/05-config:{02-typescript.mdx,03-eslint.mdx}|01-app/03-api-reference/06-cli:{create-next-app.mdx,next.mdx}|01-app/03-api-reference/07-adapters:{01-configuration.mdx,02-creating-an-adapter.mdx,03-api-reference.mdx,04-testing-adapters.mdx,05-routing-with-next-routing.mdx,06-implementing-ppr-in-an-adapter.mdx,07-runtime-integration.mdx,08-invoking-entrypoints.mdx,09-output-types.mdx,10-routing-information.mdx,11-use-cases.mdx}|02-pages/01-getting-started:{01-installation.mdx,02-project-structure.mdx,04-images.mdx,05-fonts.mdx,06-css.mdx,11-deploying.mdx}|02-pages/02-guides:{analytics.mdx,authentication.mdx,babel.mdx,ci-build-caching.mdx,content-security-policy.mdx,css-in-js.mdx,custom-server.mdx,debugging.mdx,draft-mode.mdx,environment-variables.mdx,forms.mdx,incremental-static-regeneration.mdx,instrumentation.mdx,internationalization.mdx,lazy-loading.mdx,mdx.mdx,multi-zones.mdx,open-telemetry.mdx,package-bundling.mdx,post-css.mdx,preview-mode.mdx,production-checklist.mdx,redirecting.mdx,sass.mdx,scripts.mdx,self-hosting.mdx,static-exports.mdx,tailwind-v3-css.mdx,third-party-libraries.mdx}|02-pages/02-guides/migrating:{app-router-migration.mdx,from-create-react-app.mdx,from-vite.mdx}|02-pages/02-guides/testing:{cypress.mdx,jest.mdx,playwright.mdx,vitest.mdx}|02-pages/02-guides/upgrading:{codemods.mdx,version-10.mdx,version-11.mdx,version-12.mdx,version-13.mdx,version-14.mdx,version-9.mdx}|02-pages/03-building-your-application/01-routing:{01-pages-and-layouts.mdx,02-dynamic-routes.mdx,03-linking-and-navigating.mdx,05-custom-app.mdx,06-custom-document.mdx,07-api-routes.mdx,08-custom-error.mdx}|02-pages/03-building-your-application/02-rendering:{01-server-side-rendering.mdx,02-static-site-generation.mdx,04-automatic-static-optimization.mdx,05-client-side-rendering.mdx}|02-pages/03-building-your-application/03-data-fetching:{01-get-static-props.mdx,02-get-static-paths.mdx,03-forms-and-mutations.mdx,03-get-server-side-props.mdx,05-client-side.mdx}|02-pages/03-building-your-application/06-configuring:{12-error-handling.mdx}|02-pages/04-api-reference:{06-edge.mdx,08-turbopack.mdx}|02-pages/04-api-reference/01-components:{font.mdx,form.mdx,head.mdx,image-legacy.mdx,image.mdx,link.mdx,script.mdx}|02-pages/04-api-reference/02-file-conventions:{instrumentation.mdx,proxy.mdx,public-folder.mdx,src-folder.mdx}|02-pages/04-api-reference/03-functions:{get-initial-props.mdx,get-server-side-props.mdx,get-static-paths.mdx,get-static-props.mdx,next-request.mdx,next-response.mdx,use-params.mdx,use-report-web-vitals.mdx,use-router.mdx,use-search-params.mdx,userAgent.mdx}|02-pages/04-api-reference/04-config/01-next-config-js:{adapterPath.mdx,allowedDevOrigins.mdx,assetPrefix.mdx,basePath.mdx,bundlePagesRouterDependencies.mdx,compress.mdx,crossOrigin.mdx,deploymentId.mdx,devIndicators.mdx,distDir.mdx,env.mdx,exportPathMap.mdx,generateBuildId.mdx,generateEtags.mdx,headers.mdx,httpAgentOptions.mdx,images.mdx,logging.mdx,onDemandEntries.mdx,optimizePackageImports.mdx,output.mdx,pageExtensions.mdx,poweredByHeader.mdx,productionBrowserSourceMaps.mdx,proxyClientMaxBodySize.mdx,reactStrictMode.mdx,redirects.mdx,rewrites.mdx,serverExternalPackages.mdx,trailingSlash.mdx,transpilePackages.mdx,turbopack.mdx,typescript.mdx,urlImports.mdx,useLightningcss.mdx,webVitalsAttribution.mdx,webpack.mdx}|02-pages/04-api-reference/04-config:{01-typescript.mdx,02-eslint.mdx}|02-pages/04-api-reference/05-cli:{create-next-app.mdx,next.mdx}|02-pages/04-api-reference/06-adapters:{01-configuration.mdx,02-creating-an-adapter.mdx,03-api-reference.mdx,04-testing-adapters.mdx,05-routing-with-next-routing.mdx,06-implementing-ppr-in-an-adapter.mdx,07-runtime-integration.mdx,08-invoking-entrypoints.mdx,09-output-types.mdx,10-routing-information.mdx,11-use-cases.mdx}|03-architecture:{accessibility.mdx,fast-refresh.mdx,nextjs-compiler.mdx,supported-browsers.mdx}|04-community:{01-contribution-guide.mdx,02-rspack.mdx}<!-- NEXT-AGENTS-MD-END -->
