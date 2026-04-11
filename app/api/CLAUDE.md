# app/api

REST interface for platform: authentication, task orchestration, GitHub access, connectors, MCP, sandboxes, and token management.

## Domain Purpose
- Many routes are user-scoped, but auth mode varies by route: session-only, API token, or mixed
- Dual-auth exists for selected surfaces such as MCP and token-backed task flows, not every endpoint
- Static-string logging only (no dynamic values)

## Local Patterns
- Import `getAuthFromRequest(request)` from `@/lib/auth/api-token` for dual Bearer/session auth
- Session-only routes: `getServerSession()` or `getSessionFromReq(request)`
- User-owned resources should include `eq(table.userId, user.id)` filtering
- Return `401 Unauthorized` when the route requires auth and the caller is not authenticated

## Route Subdirectories
- `auth/` - OAuth, session creation, GitHub connect/disconnect, sign-out, rate-limit info
- `tasks/` - Task CRUD, sandbox control, file ops, PR management, follow-ups, messages
- `github/` - GitHub API proxy (user, repos, orgs, verify, create)
- `repos/` - Repository metadata (commits, issues, pull requests, PR check/close helpers)
- `connectors/` - MCP server CRUD with encrypted env vars
- `mcp/` - MCP protocol HTTP handler with Bearer auth
- `api-keys/` - User API key management (list/create and check availability)
- `tokens/` - External API token generation, listing, revocation
- `sandboxes/` - Sandbox metadata and control
- `vercel/` - Vercel-specific operations (teams)
- `github-stars/` - GitHub stars utility endpoint

## Integration Points
- **Database**: `@/lib/db/client` (Drizzle + PostgreSQL)
- **Sandbox**: `@/lib/sandbox/` (creation, git ops, agent execution)
- **Auth**: `@/lib/auth/`, `@/lib/session/` (JWE sessions, OAuth)
- **Rate Limit**: `@/lib/utils/rate-limit.ts`
- **MCP Tools**: `@/lib/mcp/tools/`

## Key Files
- `route.ts` - Each route file handles one endpoint or endpoint family with route-specific auth and validation
- Routes commonly use Zod schemas (for example `insertTaskSchema`) for request validation
- Promise-based params are used where App Router passes async route params
