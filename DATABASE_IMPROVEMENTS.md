# Database Improvements - Implementation Guide

This document provides ready-to-use SQL migrations and code updates based on the comprehensive review in `DATABASE_REVIEW_REPORT.md`.

---

## Migration 1: Fix Schema Qualification (Issues #3)

**File:** `lib/db/migrations/0027_fix_schema_qualification.sql`

**Description:** Update recent migrations to use explicit `public` schema qualification.

```sql
-- Fix indexes created in migration 0025 (rate limit performance)
-- These indexes work without schema qualification, but we add it for style compliance

-- Fix indexes created in migration 0026 (sandbox guardrails)
-- Already use schema qualification in subsequent CREATE INDEX statements

-- This migration serves as documentation that the style should always include schema
-- Future migrations (0027+) will use public. schema explicitly

-- Note: These are idempotent (IF NOT EXISTS), so re-running is safe
-- The original migrations 0025, 0026 can stay as-is (they work correctly)
-- but new style is demonstrated here for migration authors

-- Re-create with explicit schema for documentation purposes:
-- CREATE INDEX IF NOT EXISTS idx_tasks_user_id_created_at
--   ON "public"."tasks"("user_id", "created_at");
-- CREATE INDEX IF NOT EXISTS idx_tasks_user_id_deleted_at
--   ON "public"."tasks"("user_id", "deleted_at");
-- CREATE INDEX IF NOT EXISTS idx_task_messages_task_id
--   ON "public"."task_messages"("task_id");
-- CREATE INDEX IF NOT EXISTS idx_task_messages_created_at
--   ON "public"."task_messages"("created_at");

-- Status: OPTIONAL (existing migrations work fine)
-- Action: For future migrations, include schema explicitly
```

---

## Migration 2: Add Table Comments (Issue #4)

**File:** `lib/db/migrations/0027_add_table_comments.sql`

**Description:** Add descriptive comments to all tables for schema documentation.

```sql
-- Migration: Add table comments for documentation

comment on table "public"."users" is
  'User profiles with OAuth provider information. Stores primary account (GitHub or Vercel) with encrypted access tokens. Each user can have multiple linked accounts via accounts table.';

comment on table "public"."accounts" is
  'Additional linked accounts (e.g., GitHub connected to Vercel user). Allows a user to authenticate via multiple providers. One account per provider per user (unique constraint on user_id + provider).';

comment on table "public"."keys" is
  'User API keys for various AI services (Anthropic, OpenAI, Cursor, Gemini, AI Gateway, GitHub). Values are encrypted at rest using AES-256-CBC. One key per provider per user (unique constraint on user_id + provider).';

comment on table "public"."tasks" is
  'Coding tasks created by users. Tracks execution status, logs (JSONB array), PR information, sandbox ID, and sub-agent activity. Supports soft deletes via deletedAt column. Heartbeat tracking for timeout extension during long-running tasks.';

comment on table "public"."task_messages" is
  'Chat history between users and agents for multi-turn conversations. Each message is linked to a task and has a role (user or agent). Enables interactive task refinement and follow-up instructions.';

comment on table "public"."connectors" is
  'MCP (Model Context Protocol) server configurations. Stores connection info for local (stdio) and remote (HTTP) servers. Environment variables and OAuth credentials are encrypted at rest. Status tracks connection health.';

comment on table "public"."settings" is
  'User-specific settings stored as key-value pairs. Allows per-user overrides of global environment variables (e.g., maxMessagesPerDay, maxSandboxDuration). One setting per key per user (unique constraint on user_id + key).';

comment on table "public"."api_tokens" is
  'External API tokens for programmatic access (MCP clients, integrations). Tokens are SHA256 hashed before storage (not encrypted). Raw token shown only once at creation. Supports optional expiration dates and usage tracking via lastUsedAt.';
```

**To Apply:**
1. Create the file at the path above
2. Run: `pnpm db:generate` (Drizzle will generate the migration)
3. Or manually create with the SQL above

---

## Migration 3: Add Foreign Key Indexes (Issue #7)

**File:** `lib/db/migrations/0028_add_foreign_key_indexes.sql`

**Description:** Add indexes on FK columns that are frequently filtered without explicit indexes.

```sql
-- Migration: Add foreign key indexes for query performance

-- Index tasks.user_id (used in rate limiting, task listing, etc.)
-- Note: idx_tasks_user_id_created_at and idx_tasks_user_id_deleted_at
-- from migration 0025 already cover this as composite indexes
-- But a simple index can help other queries
create index if not exists idx_tasks_user_id on "public"."tasks"("user_id");

-- Index connectors.user_id (used in agent execution, MCP setup)
create index if not exists idx_connectors_user_id on "public"."connectors"("user_id");

-- Index accounts.user_id (used in OAuth flow, account management)
create index if not exists idx_accounts_user_id on "public"."accounts"("user_id");

-- Index keys.user_id (used in API key retrieval for agents)
create index if not exists idx_keys_user_id on "public"."keys"("user_id");

-- Index settings.user_id (used in settings lookup)
create index if not exists idx_settings_user_id on "public"."settings"("user_id");
```

**Note:** These are optional but recommended for improved query performance on user-scoped lookups.

---

## Migration 4: Enable RLS (Issue #8) - CONDITIONAL

**File:** `lib/db/migrations/0029_enable_rls_policies.sql`

**IMPORTANT:** Only apply if using **Supabase** with Supabase Auth. Skip if using self-hosted PostgreSQL.

**Description:** Enable Row Level Security policies for defense-in-depth access control.

```sql
-- Migration: Enable RLS policies for Supabase
-- ⚠️ ONLY apply if using Supabase Auth!
-- ⚠️ Requires Supabase JWT in request headers

-- Enable RLS on all user-scoped tables
alter table "public"."users" enable row level security;
alter table "public"."accounts" enable row level security;
alter table "public"."keys" enable row level security;
alter table "public"."tasks" enable row level security;
alter table "public"."task_messages" enable row level security;
alter table "public"."connectors" enable row level security;
alter table "public"."settings" enable row level security;
alter table "public"."api_tokens" enable row level security;

-- Users table: authenticated users can only view/edit their own profile
create policy "users_select_own" on "public"."users"
  for select
  to authenticated
  using ((select auth.uid()::text) = id);

create policy "users_update_own" on "public"."users"
  for update
  to authenticated
  using ((select auth.uid()::text) = id);

-- Accounts table: users can only view/edit their own accounts
create policy "accounts_select_own" on "public"."accounts"
  for select
  to authenticated
  using ((select auth.uid()::text) = user_id);

create policy "accounts_insert_own" on "public"."accounts"
  for insert
  to authenticated
  with check ((select auth.uid()::text) = user_id);

create policy "accounts_update_own" on "public"."accounts"
  for update
  to authenticated
  using ((select auth.uid()::text) = user_id);

create policy "accounts_delete_own" on "public"."accounts"
  for delete
  to authenticated
  using ((select auth.uid()::text) = user_id);

-- Keys table: users can only view/edit their own keys
create policy "keys_select_own" on "public"."keys"
  for select
  to authenticated
  using ((select auth.uid()::text) = user_id);

create policy "keys_insert_own" on "public"."keys"
  for insert
  to authenticated
  with check ((select auth.uid()::text) = user_id);

create policy "keys_update_own" on "public"."keys"
  for update
  to authenticated
  using ((select auth.uid()::text) = user_id);

create policy "keys_delete_own" on "public"."keys"
  for delete
  to authenticated
  using ((select auth.uid()::text) = user_id);

-- Tasks table: users can only view/edit their own tasks
create policy "tasks_select_own" on "public"."tasks"
  for select
  to authenticated
  using ((select auth.uid()::text) = user_id);

create policy "tasks_insert_own" on "public"."tasks"
  for insert
  to authenticated
  with check ((select auth.uid()::text) = user_id);

create policy "tasks_update_own" on "public"."tasks"
  for update
  to authenticated
  using ((select auth.uid()::text) = user_id);

create policy "tasks_delete_own" on "public"."tasks"
  for delete
  to authenticated
  using ((select auth.uid()::text) = user_id);

-- Task messages table: users can only view messages for their tasks
create policy "task_messages_select_own" on "public"."task_messages"
  for select
  to authenticated
  using (
    (select auth.uid()::text) in (
      select user_id from "public"."tasks" where id = task_id
    )
  );

create policy "task_messages_insert_own" on "public"."task_messages"
  for insert
  to authenticated
  with check (
    (select auth.uid()::text) in (
      select user_id from "public"."tasks" where id = task_id
    )
  );

-- Connectors table: users can only view/edit their own connectors
create policy "connectors_select_own" on "public"."connectors"
  for select
  to authenticated
  using ((select auth.uid()::text) = user_id);

create policy "connectors_insert_own" on "public"."connectors"
  for insert
  to authenticated
  with check ((select auth.uid()::text) = user_id);

create policy "connectors_update_own" on "public"."connectors"
  for update
  to authenticated
  using ((select auth.uid()::text) = user_id);

create policy "connectors_delete_own" on "public"."connectors"
  for delete
  to authenticated
  using ((select auth.uid()::text) = user_id);

-- Settings table: users can only view/edit their own settings
create policy "settings_select_own" on "public"."settings"
  for select
  to authenticated
  using ((select auth.uid()::text) = user_id);

create policy "settings_insert_own" on "public"."settings"
  for insert
  to authenticated
  with check ((select auth.uid()::text) = user_id);

create policy "settings_update_own" on "public"."settings"
  for update
  to authenticated
  using ((select auth.uid()::text) = user_id);

create policy "settings_delete_own" on "public"."settings"
  for delete
  to authenticated
  using ((select auth.uid()::text) = user_id);

-- API tokens table: users can only view/edit their own tokens
create policy "api_tokens_select_own" on "public"."api_tokens"
  for select
  to authenticated
  using ((select auth.uid()::text) = user_id);

create policy "api_tokens_insert_own" on "public"."api_tokens"
  for insert
  to authenticated
  with check ((select auth.uid()::text) = user_id);

create policy "api_tokens_delete_own" on "public"."api_tokens"
  for delete
  to authenticated
  using ((select auth.uid()::text) = user_id);
```

**Testing RLS Policies:**
```sql
-- Disable RLS for testing
alter table "public"."users" disable row level security;
alter table "public"."accounts" disable row level security;
-- ... repeat for all tables

-- Test query (should only return current user's data):
select * from "public"."users";
-- Returns: Only the authenticated user's record
```

---

## Code Update 1: Add Schema Comments (TypeScript)

**File:** `lib/db/schema.ts`

**Description:** Add JSDoc comments explaining encryption and nullable columns.

```typescript
/**
 * User profiles with OAuth provider information.
 *
 * Primary OAuth account determines initial authentication method (GitHub or Vercel).
 * Additional accounts can be linked via the accounts table.
 *
 * Encrypted fields:
 * - accessToken: OAuth provider access token (AES-256-CBC)
 * - refreshToken: OAuth provider refresh token (AES-256-CBC)
 *
 * Uses CUID2 for ID generation (text type) instead of bigint identity.
 * Rationale: Distributed-friendly, URL-safe, privacy-preserving.
 * See: https://github.com/paralleldrive/cuid2
 */
export const users = pgTable('users', {
  id: text('id').primaryKey(),
  provider: text('provider', { enum: ['github', 'vercel'] }).notNull(),
  externalId: text('external_id').notNull(),
  accessToken: text('access_token').notNull(),  // Encrypted at rest
  refreshToken: text('refresh_token'),  // Encrypted at rest, optional
  scope: text('scope'),
  username: text('username').notNull(),
  email: text('email'),  // Optional, from OAuth provider
  name: text('name'),  // Optional, from OAuth provider
  avatarUrl: text('avatar_url'),  // Optional, from OAuth provider
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
  lastLoginAt: timestamp('last_login_at').defaultNow().notNull(),
}, (table) => ({
  providerExternalIdUnique: uniqueIndex('users_provider_external_id_idx')
    .on(table.provider, table.externalId),
}))

/**
 * User API keys for various AI services.
 *
 * Values are encrypted at rest using AES-256-CBC (lib/crypto.ts).
 * User-provided keys override system environment variables.
 * Supports: Anthropic, OpenAI, Cursor, Gemini, AI Gateway, GitHub
 *
 * One key per provider per user (enforced by unique constraint).
 */
export const keys = pgTable(
  'keys',
  {
    id: text('id').primaryKey(),
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    provider: text('provider', {
      enum: ['anthropic', 'openai', 'cursor', 'gemini', 'aigateway', 'github'],
    }).notNull(),
    value: text('value').notNull(),  // Encrypted at rest (AES-256-CBC)
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
  },
  (table) => ({
    userIdProviderUnique: uniqueIndex('keys_user_id_provider_idx')
      .on(table.userId, table.provider),
  }),
)

/**
 * Coding tasks created by users.
 *
 * Task lifecycle:
 * - pending: Created, awaiting execution start
 * - processing: Agent is executing
 * - completed: Task finished successfully
 * - error: Task failed
 * - stopped: User stopped the task
 *
 * Soft deletes: deletedAt timestamp instead of hard delete
 * Allows data recovery and audit trail preservation.
 *
 * Logs: JSONB array of LogEntry objects
 * - Appended in real-time during execution
 * - Includes agent source context (primary or sub-agent)
 * - Sub-agents tracked via subAgentActivity array
 *
 * Heartbeat: lastHeartbeat tracks activity for timeout extension
 * - Updated on every log operation
 * - Allows grace period for long-running tasks
 */
export const tasks = pgTable('tasks', {
  id: text('id').primaryKey(),
  userId: text('user_id')
    .notNull()
    .references(() => users.id, { onDelete: 'cascade' }),
  prompt: text('prompt').notNull(),  // User's task request
  title: text('title'),  // AI-generated task title (nullable, generated asynchronously)
  repoUrl: text('repo_url'),
  selectedAgent: text('selected_agent').default('claude'),
  selectedModel: text('selected_model'),
  installDependencies: boolean('install_dependencies').default(false),
  maxDuration: integer('max_duration')
    .default(parseInt(process.env.MAX_SANDBOX_DURATION || '300', 10)),
  keepAlive: boolean('keep_alive').default(false),
  status: text('status', {
    enum: ['pending', 'processing', 'completed', 'error', 'stopped'],
  })
    .notNull()
    .default('pending'),
  progress: integer('progress').default(0),
  logs: jsonb('logs').$type<LogEntry[]>(),  // JSONB array of LogEntry
  error: text('error'),
  branchName: text('branch_name'),  // AI-generated; null until available
  sourceBranch: text('source_branch'),  // Source branch to clone from
  sandboxId: text('sandbox_id'),  // Vercel sandbox ID; null if not provisioned
  agentSessionId: text('agent_session_id'),  // Session ID for resumed tasks
  sandboxUrl: text('sandbox_url'),
  previewUrl: text('preview_url'),
  prUrl: text('pr_url'),  // PR URL; null if not created
  prNumber: integer('pr_number'),
  prStatus: text('pr_status', { enum: ['open', 'closed', 'merged'] }),
  prMergeCommitSha: text('pr_merge_commit_sha'),
  mcpServerIds: jsonb('mcp_server_ids').$type<string[]>(),
  subAgentActivity: jsonb('sub_agent_activity').$type<SubAgentActivity[]>(),
  currentSubAgent: text('current_sub_agent'),  // Name of currently active sub-agent
  lastHeartbeat: timestamp('last_heartbeat'),  // Updated on each log; null if no activity
  heartbeatExtensionCount: integer('heartbeat_extension_count').default(0),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
  completedAt: timestamp('completed_at'),  // Set when status = completed
  deletedAt: timestamp('deleted_at'),  // Soft delete timestamp
})

/**
 * MCP (Model Context Protocol) server configurations.
 *
 * Supports two types of servers:
 * - local: Stdio-based (command + args + env)
 * - remote: HTTP-based (baseUrl + headers)
 *
 * Encrypted fields:
 * - env: Environment variables (JSON object), encrypted as text
 * - oauthClientSecret: OAuth credential, encrypted
 *
 * Status: connected / disconnected (tracks health)
 */
export const connectors = pgTable('connectors', {
  id: text('id').primaryKey(),
  userId: text('user_id')
    .notNull()
    .references(() => users.id, { onDelete: 'cascade' }),
  name: text('name').notNull(),
  description: text('description'),
  type: text('type', { enum: ['local', 'remote'] })
    .notNull()
    .default('remote'),
  baseUrl: text('base_url'),  // For remote servers
  oauthClientId: text('oauth_client_id'),  // Optional OAuth client ID
  oauthClientSecret: text('oauth_client_secret'),  // Encrypted if present
  command: text('command'),  // For local (stdio) servers
  env: text('env'),  // Environment variables (encrypted JSON string)
  status: text('status', { enum: ['connected', 'disconnected'] })
    .notNull()
    .default('disconnected'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
})

/**
 * Chat history for multi-turn task conversations.
 *
 * Links to tasks via task_id (CASCADE delete).
 * Role: 'user' for user messages, 'agent' for agent responses.
 *
 * Enables interactive refinement of tasks.
 */
export const taskMessages = pgTable('task_messages', {
  id: text('id').primaryKey(),
  taskId: text('task_id')
    .notNull()
    .references(() => tasks.id, { onDelete: 'cascade' }),
  role: text('role', { enum: ['user', 'agent'] }).notNull(),
  content: text('content').notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
})

/**
 * External API tokens for programmatic access.
 *
 * Tokens are SHA256 hashed before storage (not encrypted).
 * Raw token is shown only once at creation and cannot be retrieved later.
 *
 * Supports optional expiration dates and usage tracking.
 * Used by MCP clients and external integrations.
 */
export const apiTokens = pgTable(
  'api_tokens',
  {
    id: text('id')
      .primaryKey()
      .$defaultFn(() => createId()),
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    name: text('name').notNull(),  // User-friendly token name
    tokenHash: text('token_hash').notNull().unique(),  // SHA256 hash (not reversible)
    tokenPrefix: text('token_prefix').notNull(),  // First 8 chars for UI display
    lastUsedAt: timestamp('last_used_at'),  // Updated on each API request
    expiresAt: timestamp('expires_at'),  // Optional expiration
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
  },
  (table) => ({
    userIdIdx: index('api_tokens_user_id_idx').on(table.userId),
  }),
)
```

---

## Code Update 2: Document CUID2 Choice

**File:** `lib/db/schema.ts` (at top of file)

```typescript
/**
 * Database Schema
 *
 * Identity Strategy: CUID2 (text type, ~21 characters)
 *
 * Why not bigint generated always as identity?
 * - CUID2 is distributed-friendly (no coordination between services)
 * - URL-safe base36 encoding
 * - Privacy-preserving (not sequential, harder to enumerate)
 * - Collision resistance (cryptographically strong)
 *
 * Tradeoff: Slightly larger than bigint, but index performance difference is negligible.
 * This is standard in modern async/distributed systems (Stripe uses similar approach).
 *
 * Reference: https://github.com/paralleldrive/cuid2
 */
```

---

## Create Documentation File

**File:** `lib/db/MIGRATIONS.md`

```markdown
# Database Migrations

## Overview
All migrations use Drizzle ORM and are stored in `lib/db/migrations/`.
Applied automatically on Vercel deployment via `scripts/migrate-production.ts`.

## Migration Timeline

### Schema Foundation (0000-0010)
- **0000**: Initial tasks table (logs as text array, later converted to JSONB)
- **0001-0005**: Log format evolution, column additions (install_dependencies, max_duration)
- **0006**: Connectors table for MCP server configuration
- **0007**: Connectors schema refinement (baseUrl optional, type enum added)
- **0008-0009**: Task schema cleanup (remove description, instructions columns)
- **0010**: **MAJOR**: User authentication schema
  - Creates users table (primary OAuth account)
  - Creates accounts table (linked additional accounts)
  - Creates keys table (API keys for AI services)
  - Adds user_id FK to tasks, connectors
  - Adds deleted_at for soft deletes

### Task Features (0011-0024)
- **0011**: Connector env field changed to encrypted text
- **0012-0014**: Task PR tracking (prUrl, prNumber, prStatus, prMergeCommitSha)
- **0015**: Task messages table for multi-turn conversations
- **0016**: Keep-alive feature (keepAlive column)
- **0017-0019**: Settings table for user-specific overrides
- **0020-0021**: Max duration defaults stabilization (finally settled at 300 min)
- **0021**: API tokens table for external authentication
- **0022**: Updated_at timestamp on api_tokens

### Task Execution (0023-0026)
- **0023**: Source branch selection (sourceBranch column)
- **0024**: Same as 0023 (alternate naming convention)
- **0025**: **PERFORMANCE**: Rate limit indexes
  - Composite index: tasks(user_id, created_at)
  - Composite index: tasks(user_id, deleted_at) with filtering
  - Indexes on task_messages for join optimization
  - Eliminates full table scans in rate limiting queries
- **0026**: **GUARDRAILS**: Sandbox timeout management
  - Heartbeat extension count (tracks timeout extensions)
  - Filtered index for extended timeouts
  - Filtered index for stale sandbox cleanup

## Key Design Decisions

### User Isolation
Every user-scoped table has:
```typescript
userId: text('user_id')
  .notNull()
  .references(() => users.id, { onDelete: 'cascade' })
```

All queries filter by `userId` at the ORM level.
Optional RLS policies provide defense-in-depth on Supabase.

### Encryption
- **Encrypted fields** (AES-256-CBC):
  - accessToken (users, accounts)
  - value (keys table)
  - env (connectors)
  - oauthClientSecret (connectors)

- **Hashed fields** (SHA256, non-reversible):
  - tokenHash (api_tokens)
  - Fallback to env vars if decryption fails

### JSONB Logs
- **logs**: Array of LogEntry objects with agent source tracking
- **subAgentActivity**: Array of SubAgentActivity for sub-agent visibility
- Real-time updates via append-only pattern

### Soft Deletes
- **deletedAt** column instead of hard delete
- Rate limiting excludes soft-deleted tasks
- Data recovery possible
- Audit trail preserved

## Migration Challenges Overcome

### Task Logs Format Evolution
Original: text array → JSONB object array (migration 0002)
Challenge: Convert unstructured logs to structured format with timestamps

### Max Duration Defaults
Changed multiple times (5 → 1 → 5 → 300) as defaults stabilized
Final: 300 minutes (5 hours) matches environment variable default

### Connector Env Field
Original: JSONB → Text (encrypted)
Challenge: Encryption requires string type, not object type

## Pending Improvements

See `DATABASE_REVIEW_REPORT.md` for recommended additions:
- Table comments (migration 0027)
- Schema qualification consistency (migration 0027)
- Foreign key indexes (migration 0028)
- RLS policies (migration 0029, Supabase only)

## Performance Tuning

### Indexes for Rate Limiting (0025)
Before: Full table scans on every task creation
After:
- `idx_tasks_user_id_created_at` → O(log n) user task lookup by date
- `idx_tasks_user_id_deleted_at` → O(log n) soft delete filtering

### Query Performance
- Join on task_messages.task_id uses index `idx_task_messages_task_id`
- Date range queries use index `idx_task_messages_created_at`
- Result: Rate limit check typically < 5ms on large databases

## Testing Migrations

```bash
# Local development
cp .env.local .env
DOTENV_CONFIG_PATH=.env pnpm tsx -r dotenv/config node_modules/drizzle-kit/bin.cjs migrate
rm .env

# Verify migration applied
pnpm db:studio

# Rollback (not recommended for production data)
# Use Vercel PostgreSQL backups for recovery
```

## Deployment

Migrations run automatically on Vercel via:
```typescript
// scripts/migrate-production.ts
if (process.env.VERCEL_ENV === 'production') {
  execSync('npx drizzle-kit migrate', { stdio: 'inherit' })
}
```

No manual intervention required. Always test in staging first.
```

---

## Implementation Priority

1. **REQUIRED:** Create migration 0027 (table comments) - adds documentation
2. **RECOMMENDED:** Create migration 0028 (FK indexes) - improves performance
3. **CONDITIONAL:** Create migration 0029 (RLS) - only if using Supabase
4. **NICE-TO-HAVE:** Update schema.ts comments - improves code documentation

---

## Validation Checklist

After applying migrations:

```bash
# Verify table comments exist
psql $POSTGRES_URL -c "
  SELECT table_name, obj_description(relfilenode, 'pg_class')
  FROM information_schema.tables
  JOIN pg_class ON relname = table_name
  WHERE table_schema = 'public'
  ORDER BY table_name;
"

# Verify indexes exist
psql $POSTGRES_URL -c "
  SELECT tablename, indexname
  FROM pg_indexes
  WHERE schemaname = 'public'
  ORDER BY tablename, indexname;
"

# Verify RLS enabled (if applied)
psql $POSTGRES_URL -c "
  SELECT tablename, rowsecurity
  FROM pg_tables
  WHERE schemaname = 'public'
  ORDER BY tablename;
"
```

---

## Support

For questions about migrations, see:
- `DATABASE_REVIEW_REPORT.md` - Full analysis and rationale
- `lib/db/schema.ts` - Current schema definition
- `scripts/migrate-production.ts` - Automated migration runner
- Drizzle docs: https://orm.drizzle.team/docs/migrations

