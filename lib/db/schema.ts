import { pgTable, text, timestamp, integer, jsonb, boolean, uniqueIndex, index } from 'drizzle-orm/pg-core'
import { createId } from '@paralleldrive/cuid2'
import { z } from 'zod'

// Sub-agent activity schema for tracking spawned sub-agents
// Length limits prevent database bloat from malicious/buggy agents
export const subAgentActivitySchema = z.object({
  id: z.string().min(1).max(36), // CUID2 is ~21 chars, allow up to 36
  name: z.string().min(1).max(100), // Sub-agent name (e.g., "Explore", "Plan", "general-purpose")
  type: z.string().max(50).optional(), // Sub-agent type classification
  status: z.enum(['starting', 'running', 'completed', 'error']),
  startedAt: z.string().datetime(), // ISO string format from JSONB
  completedAt: z.string().datetime().optional(), // ISO string format from JSONB
  description: z.string().max(500).optional(), // Short description of what the sub-agent is doing
})

export type SubAgentActivity = z.infer<typeof subAgentActivitySchema>

// Log entry types - extended with agent source tracking
// Length limits prevent database bloat from overly long messages
export const logEntrySchema = z.object({
  type: z.enum(['info', 'command', 'error', 'success', 'subagent']), // Added 'subagent' type
  message: z.string().max(2000), // Reasonable message length limit
  timestamp: z.string().datetime().optional(), // ISO string format from JSONB
  // Agent source tracking for sub-agent visibility
  agentSource: z
    .object({
      name: z.string().max(100), // Primary agent or sub-agent name
      isSubAgent: z.boolean().default(false),
      parentAgent: z.string().max(100).optional(), // Parent agent name if this is a sub-agent
      subAgentId: z.string().max(36).optional(), // ID linking to SubAgentActivity
    })
    .optional(),
})

export type LogEntry = z.infer<typeof logEntrySchema>

// Users table - user profile and primary OAuth account
export const users = pgTable(
  'users',
  {
    id: text('id').primaryKey(), // Internal user ID (we generate this)
    // Primary OAuth account info (how they signed in)
    provider: text('provider', {
      enum: ['github', 'vercel'],
    }).notNull(), // Primary auth provider
    externalId: text('external_id').notNull(), // External ID from OAuth provider
    accessToken: text('access_token').notNull(), // Encrypted OAuth access token
    refreshToken: text('refresh_token'), // Encrypted OAuth refresh token
    scope: text('scope'), // OAuth scope
    // Profile info
    username: text('username').notNull(),
    email: text('email'),
    name: text('name'),
    avatarUrl: text('avatar_url'),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
    lastLoginAt: timestamp('last_login_at').defaultNow().notNull(),
  },
  (table) => ({
    // Unique constraint: prevent duplicate signups from same provider + external ID
    providerExternalIdUnique: uniqueIndex('users_provider_external_id_idx').on(table.provider, table.externalId),
  }),
)

export const insertUserSchema = z.object({
  id: z.string().optional(), // Auto-generated if not provided
  provider: z.enum(['github', 'vercel']),
  externalId: z.string().min(1, 'External ID is required'),
  accessToken: z.string(),
  refreshToken: z.string().optional(),
  scope: z.string().optional(),
  username: z.string().min(1, 'Username is required'),
  email: z.string().email().optional(),
  name: z.string().optional(),
  avatarUrl: z.string().url().optional(),
  createdAt: z.date().optional(),
  updatedAt: z.date().optional(),
  lastLoginAt: z.date().optional(),
})

export const selectUserSchema = z.object({
  id: z.string(),
  provider: z.enum(['github', 'vercel']),
  externalId: z.string(),
  accessToken: z.string(),
  refreshToken: z.string().nullable(),
  scope: z.string().nullable(),
  username: z.string(),
  email: z.string().nullable(),
  name: z.string().nullable(),
  avatarUrl: z.string().nullable(),
  createdAt: z.date(),
  updatedAt: z.date(),
  lastLoginAt: z.date(),
})

export type User = z.infer<typeof selectUserSchema>
export type InsertUser = z.infer<typeof insertUserSchema>

export const tasks = pgTable(
  'tasks',
  {
    id: text('id').primaryKey(),
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }), // Foreign key to users table
    prompt: text('prompt').notNull(),
    title: text('title'),
    repoUrl: text('repo_url'),
    selectedAgent: text('selected_agent').default('claude'),
    selectedModel: text('selected_model'),
    installDependencies: boolean('install_dependencies').default(false),
    maxDuration: integer('max_duration').default(300),
    keepAlive: boolean('keep_alive').default(false),
    status: text('status', {
      enum: ['pending', 'processing', 'completed', 'error', 'stopped'],
    })
      .notNull()
      .default('pending'),
    progress: integer('progress').default(0),
    logs: jsonb('logs').$type<LogEntry[]>(),
    error: text('error'),
    branchName: text('branch_name'), // New branch name created by agent for changes
    sourceBranch: text('source_branch'), // Source branch to clone from (defaults to repository default branch)
    sandboxId: text('sandbox_id'),
    agentSessionId: text('agent_session_id'),
    sandboxUrl: text('sandbox_url'),
    previewUrl: text('preview_url'),
    prUrl: text('pr_url'),
    prNumber: integer('pr_number'),
    prStatus: text('pr_status', {
      enum: ['open', 'closed', 'merged'],
    }),
    prMergeCommitSha: text('pr_merge_commit_sha'),
    mcpServerIds: jsonb('mcp_server_ids').$type<string[]>(),
    // Sub-agent tracking for visibility and timeout handling
    subAgentActivity: jsonb('sub_agent_activity').$type<SubAgentActivity[]>(),
    currentSubAgent: text('current_sub_agent'), // Name of currently active sub-agent
    lastHeartbeat: timestamp('last_heartbeat'), // Last activity timestamp for timeout extension
    heartbeatExtensionCount: integer('heartbeat_extension_count').default(0), // Track timeout extensions
    // Sandbox mode and snapshot fields (Phase 0 scaffold — consumers added in Phase 1+)
    // sandboxMode values: 'ephemeral' | 'persistent' | 'fresh'
    sandboxMode: text('sandbox_mode'),
    // Soft reference to sandbox_profiles.profile_key — not a hard FK (profiles may be pruned)
    setupProfileKey: text('setup_profile_key'),
    // Most recent snapshot id used for this task's sandbox restore
    snapshotId: text('snapshot_id'),
    // Soft reference to sandbox_workspaces.workspace_name — not a hard FK
    persistentWorkspaceName: text('persistent_workspace_name'),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
    completedAt: timestamp('completed_at'),
    deletedAt: timestamp('deleted_at'),
  },
  (table) => ({
    // Composite indexes for rate-limiting queries (added in migration 0025)
    userIdCreatedAtIdx: index('idx_tasks_user_id_created_at').on(table.userId, table.createdAt),
    userIdDeletedAtIdx: index('idx_tasks_user_id_deleted_at').on(table.userId, table.deletedAt),
  }),
)

// Manual Zod schemas for validation
export const insertTaskSchema = z.object({
  id: z.string().optional(),
  userId: z.string().min(1, 'User ID is required'),
  prompt: z.string().min(1, 'Prompt is required'),
  title: z.string().optional(),
  repoUrl: z.string().url('Must be a valid URL').optional(),
  selectedAgent: z.enum(['claude', 'codex', 'copilot', 'cursor', 'gemini', 'opencode']).default('claude'),
  selectedModel: z.string().optional(),
  installDependencies: z.boolean().default(false),
  maxDuration: z.number().optional(),
  keepAlive: z.boolean().default(false),
  status: z.enum(['pending', 'processing', 'completed', 'error', 'stopped']).default('pending'),
  progress: z.number().min(0).max(100).default(0),
  logs: z.array(logEntrySchema).optional(),
  error: z.string().optional(),
  branchName: z.string().optional(),
  sourceBranch: z.string().optional(),
  sandboxId: z.string().optional(),
  agentSessionId: z.string().optional(),
  sandboxUrl: z.string().optional(),
  previewUrl: z.string().optional(),
  prUrl: z.string().optional(),
  prNumber: z.number().optional(),
  prStatus: z.enum(['open', 'closed', 'merged']).optional(),
  prMergeCommitSha: z.string().optional(),
  mcpServerIds: z.array(z.string()).optional(),
  // Sub-agent tracking fields
  subAgentActivity: z.array(subAgentActivitySchema).optional(),
  currentSubAgent: z.string().optional(),
  lastHeartbeat: z.date().optional(),
  heartbeatExtensionCount: z.number().int().min(0).default(0),
  // Sandbox mode and snapshot fields (Phase 0 scaffold)
  sandboxMode: z.string().optional(),
  setupProfileKey: z.string().optional(),
  snapshotId: z.string().optional(),
  persistentWorkspaceName: z.string().optional(),
  createdAt: z.date().optional(),
  updatedAt: z.date().optional(),
  completedAt: z.date().optional(),
  deletedAt: z.date().optional(),
})

export const selectTaskSchema = z.object({
  id: z.string(),
  userId: z.string(),
  prompt: z.string(),
  title: z.string().nullable(),
  repoUrl: z.string().nullable(),
  selectedAgent: z.string().nullable(),
  selectedModel: z.string().nullable(),
  installDependencies: z.boolean().nullable(),
  maxDuration: z.number().nullable(),
  keepAlive: z.boolean().nullable(),
  status: z.enum(['pending', 'processing', 'completed', 'error', 'stopped']),
  progress: z.number().nullable(),
  logs: z.array(logEntrySchema).nullable(),
  error: z.string().nullable(),
  branchName: z.string().nullable(),
  sourceBranch: z.string().nullable(),
  sandboxId: z.string().nullable(),
  agentSessionId: z.string().nullable(),
  sandboxUrl: z.string().nullable(),
  previewUrl: z.string().nullable(),
  prUrl: z.string().nullable(),
  prNumber: z.number().nullable(),
  prStatus: z.enum(['open', 'closed', 'merged']).nullable(),
  prMergeCommitSha: z.string().nullable(),
  mcpServerIds: z.array(z.string()).nullable(),
  // Sub-agent tracking fields
  subAgentActivity: z.array(subAgentActivitySchema).nullable(),
  currentSubAgent: z.string().nullable(),
  lastHeartbeat: z.date().nullable(),
  heartbeatExtensionCount: z.number().int().min(0),
  // Sandbox mode and snapshot fields (Phase 0 scaffold)
  sandboxMode: z.string().nullable(),
  setupProfileKey: z.string().nullable(),
  snapshotId: z.string().nullable(),
  persistentWorkspaceName: z.string().nullable(),
  createdAt: z.date(),
  updatedAt: z.date(),
  completedAt: z.date().nullable(),
  deletedAt: z.date().nullable(),
})

export type Task = z.infer<typeof selectTaskSchema>
export type InsertTask = z.infer<typeof insertTaskSchema>

export const connectors = pgTable('connectors', {
  id: text('id').primaryKey(),
  userId: text('user_id')
    .notNull()
    .references(() => users.id, { onDelete: 'cascade' }), // Foreign key to users table
  name: text('name').notNull(),
  description: text('description'),
  type: text('type', {
    enum: ['local', 'remote'],
  })
    .notNull()
    .default('remote'),
  // For remote MCP servers
  baseUrl: text('base_url'),
  oauthClientId: text('oauth_client_id'),
  oauthClientSecret: text('oauth_client_secret'),
  // For local MCP servers
  command: text('command'),
  // Environment variables (for both local and remote) - stored encrypted
  env: text('env'),
  status: text('status', {
    enum: ['connected', 'disconnected'],
  })
    .notNull()
    .default('disconnected'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
})

export const insertConnectorSchema = z.object({
  id: z.string().optional(),
  userId: z.string(),
  name: z.string().min(1, 'Name is required'),
  description: z.string().optional(),
  type: z.enum(['local', 'remote']).default('remote'),
  // For remote MCP servers
  baseUrl: z.string().url('Must be a valid URL').optional(),
  oauthClientId: z.string().optional(),
  oauthClientSecret: z.string().optional(),
  // For local MCP servers
  command: z.string().optional(),
  // Environment variables (for both local and remote) - will be encrypted
  env: z.record(z.string(), z.string()).optional(),
  status: z.enum(['connected', 'disconnected']).default('disconnected'),
  createdAt: z.date().optional(),
  updatedAt: z.date().optional(),
})

export const selectConnectorSchema = z.object({
  id: z.string(),
  userId: z.string(),
  name: z.string(),
  description: z.string().nullable(),
  type: z.enum(['local', 'remote']),
  // For remote MCP servers
  baseUrl: z.string().nullable(),
  oauthClientId: z.string().nullable(),
  oauthClientSecret: z.string().nullable(),
  // For local MCP servers
  command: z.string().nullable(),
  // Environment variables (for both local and remote) - stored encrypted as string
  env: z.string().nullable(),
  status: z.enum(['connected', 'disconnected']),
  createdAt: z.date(),
  updatedAt: z.date(),
})

export type Connector = z.infer<typeof selectConnectorSchema>
export type InsertConnector = z.infer<typeof insertConnectorSchema>

// Accounts table - Additional accounts linked to users
// Currently only GitHub can be connected as an additional account
// (e.g., Vercel users can connect their GitHub account)
// Multiple users can connect to the same external account (each as a separate record)
export const accounts = pgTable(
  'accounts',
  {
    id: text('id').primaryKey(),
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }), // Foreign key to users table
    provider: text('provider', {
      enum: ['github'],
    })
      .notNull()
      .default('github'), // Only GitHub for now
    externalUserId: text('external_user_id').notNull(), // GitHub user ID
    accessToken: text('access_token').notNull(), // Encrypted OAuth access token
    refreshToken: text('refresh_token'), // Encrypted OAuth refresh token
    expiresAt: timestamp('expires_at'),
    scope: text('scope'),
    username: text('username').notNull(), // GitHub username
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
  },
  (table) => ({
    // Unique constraint: a user can only have one account per provider
    userIdProviderUnique: uniqueIndex('accounts_user_id_provider_idx').on(table.userId, table.provider),
  }),
)

export const insertAccountSchema = z.object({
  id: z.string().optional(),
  userId: z.string(),
  provider: z.enum(['github']).default('github'),
  externalUserId: z.string().min(1, 'External user ID is required'),
  accessToken: z.string(),
  refreshToken: z.string().optional(),
  expiresAt: z.date().optional(),
  scope: z.string().optional(),
  username: z.string().min(1, 'Username is required'),
  createdAt: z.date().optional(),
  updatedAt: z.date().optional(),
})

export const selectAccountSchema = z.object({
  id: z.string(),
  userId: z.string(),
  provider: z.enum(['github']),
  externalUserId: z.string(),
  accessToken: z.string(),
  refreshToken: z.string().nullable(),
  expiresAt: z.date().nullable(),
  scope: z.string().nullable(),
  username: z.string(),
  createdAt: z.date(),
  updatedAt: z.date(),
})

export type Account = z.infer<typeof selectAccountSchema>
export type InsertAccount = z.infer<typeof insertAccountSchema>

// Keys table - user's API keys for various services
// Each row represents one API key for one provider for one user
export const keys = pgTable(
  'keys',
  {
    id: text('id').primaryKey(),
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }), // Foreign key to users table
    provider: text('provider', {
      enum: ['anthropic', 'openai', 'cursor', 'gemini', 'aigateway', 'github'],
    }).notNull(),
    value: text('value').notNull(), // Encrypted API key value
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
  },
  (table) => ({
    // Unique constraint: a user can only have one key per provider
    userIdProviderUnique: uniqueIndex('keys_user_id_provider_idx').on(table.userId, table.provider),
  }),
)

export const insertKeySchema = z.object({
  id: z.string().optional(),
  userId: z.string(),
  provider: z.enum(['anthropic', 'openai', 'cursor', 'gemini', 'aigateway', 'github']),
  value: z.string().min(1, 'API key value is required'),
  createdAt: z.date().optional(),
  updatedAt: z.date().optional(),
})

export const selectKeySchema = z.object({
  id: z.string(),
  userId: z.string(),
  provider: z.enum(['anthropic', 'openai', 'cursor', 'gemini', 'aigateway', 'github']),
  value: z.string(),
  createdAt: z.date(),
  updatedAt: z.date(),
})

export type Key = z.infer<typeof selectKeySchema>
export type InsertKey = z.infer<typeof insertKeySchema>

// Task messages table - stores user and agent messages for each task
export const taskMessages = pgTable(
  'task_messages',
  {
    id: text('id').primaryKey(),
    taskId: text('task_id')
      .notNull()
      .references(() => tasks.id, { onDelete: 'cascade' }), // Foreign key to tasks table
    role: text('role', {
      enum: ['user', 'agent'],
    }).notNull(), // Who sent the message
    content: text('content').notNull(), // The message content
    createdAt: timestamp('created_at').defaultNow().notNull(),
  },
  (table) => ({
    // Indexes for join performance and date range filtering (added in migration 0025)
    taskIdIdx: index('idx_task_messages_task_id').on(table.taskId),
    createdAtIdx: index('idx_task_messages_created_at').on(table.createdAt),
  }),
)

export const insertTaskMessageSchema = z.object({
  id: z.string().optional(),
  taskId: z.string().min(1, 'Task ID is required'),
  role: z.enum(['user', 'agent']),
  content: z.string().min(1, 'Content is required'),
  createdAt: z.date().optional(),
})

export const selectTaskMessageSchema = z.object({
  id: z.string(),
  taskId: z.string(),
  role: z.enum(['user', 'agent']),
  content: z.string(),
  createdAt: z.date(),
})

export type TaskMessage = z.infer<typeof selectTaskMessageSchema>
export type InsertTaskMessage = z.infer<typeof insertTaskMessageSchema>

// Settings table - key-value pairs for overriding environment variables per user
export const settings = pgTable(
  'settings',
  {
    id: text('id').primaryKey(),
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }), // Required user reference
    key: text('key').notNull(), // Setting key (e.g., 'maxMessagesPerDay')
    value: text('value').notNull(), // Setting value (stored as text)
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
  },
  (table) => ({
    // Unique constraint: prevent duplicate keys per user
    userIdKeyUnique: uniqueIndex('settings_user_id_key_idx').on(table.userId, table.key),
  }),
)

export const insertSettingSchema = z.object({
  id: z.string().optional(),
  userId: z.string().min(1, 'User ID is required'),
  key: z.string().min(1, 'Key is required'),
  value: z.string().min(1, 'Value is required'),
  createdAt: z.date().optional(),
  updatedAt: z.date().optional(),
})

export const selectSettingSchema = z.object({
  id: z.string(),
  userId: z.string(),
  key: z.string(),
  value: z.string(),
  createdAt: z.date(),
  updatedAt: z.date(),
})

export type Setting = z.infer<typeof selectSettingSchema>
export type InsertSetting = z.infer<typeof insertSettingSchema>

// API Tokens table - user-generated API tokens for authenticating external requests
export const apiTokens = pgTable(
  'api_tokens',
  {
    id: text('id')
      .primaryKey()
      .$defaultFn(() => createId()),
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    tokenHash: text('token_hash').notNull().unique(),
    tokenPrefix: text('token_prefix').notNull(),
    lastUsedAt: timestamp('last_used_at'),
    expiresAt: timestamp('expires_at'),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
  },
  (table) => ({
    userIdIdx: index('api_tokens_user_id_idx').on(table.userId),
  }),
)

export const insertApiTokenSchema = z.object({
  id: z.string().optional(),
  userId: z.string().min(1, 'User ID is required'),
  name: z.string().min(1, 'Name is required'),
  tokenHash: z.string().min(1, 'Token hash is required'),
  tokenPrefix: z.string().min(1, 'Token prefix is required'),
  lastUsedAt: z.date().optional(),
  expiresAt: z.date().optional(),
  createdAt: z.date().optional(),
  updatedAt: z.date().optional(),
})

export const selectApiTokenSchema = z.object({
  id: z.string(),
  userId: z.string(),
  name: z.string(),
  tokenHash: z.string(),
  tokenPrefix: z.string(),
  lastUsedAt: z.date().nullable(),
  expiresAt: z.date().nullable(),
  createdAt: z.date(),
  updatedAt: z.date(),
})

export type ApiToken = z.infer<typeof selectApiTokenSchema>
export type InsertApiToken = z.infer<typeof insertApiTokenSchema>

// ============================================================
// Sandbox Profiles table — deterministic setup fingerprints
// Phase 0 scaffold: schema only; consumers added in Phase 1+
// ============================================================
// scopeType values: 'shared' | 'user' | 'org'
//   'shared' — platform-owned base tooling snapshot, no user/org restriction
//   'user'   — scoped to a single userId (private repos, user-specific setup)
//   'org'    — scoped to an orgId for shared team snapshots
export const sandboxProfiles = pgTable(
  'sandbox_profiles',
  {
    id: text('id')
      .primaryKey()
      .$defaultFn(() => createId()),
    // Deterministic fingerprint string computed from setup inputs
    profileKey: text('profile_key').notNull().unique(),
    // scopeType values: 'shared' | 'user' | 'org' (see table comment above)
    scopeType: text('scope_type').notNull(),
    // userId or orgId depending on scopeType; null for 'shared' scope
    scopeOwnerId: text('scope_owner_id'),
    // null for shared base snapshots that are not repo-specific
    repoUrl: text('repo_url'),
    // e.g. 'node24', 'node22', 'python3.13'
    runtime: text('runtime').notNull(),
    // packageManager values: 'npm' | 'pnpm' | 'yarn' | null
    packageManager: text('package_manager'),
    lockfileHash: text('lockfile_hash'),
    // Incremented when the setup pipeline changes in a breaking way
    setupVersion: integer('setup_version').notNull().default(1),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
  },
  (table) => ({
    // Enforce uniqueness on the fingerprint key
    profileKeyUnique: uniqueIndex('sandbox_profiles_profile_key_idx').on(table.profileKey),
    // Composite index for scope-based lookup
    scopeLookupIdx: index('sandbox_profiles_scope_lookup_idx').on(table.scopeType, table.scopeOwnerId, table.repoUrl),
  }),
)

export const insertSandboxProfileSchema = z.object({
  id: z.string().optional(),
  profileKey: z.string().min(1, 'Profile key is required'),
  scopeType: z.string().min(1, 'Scope type is required'),
  scopeOwnerId: z.string().optional(),
  repoUrl: z.string().optional(),
  runtime: z.string().min(1, 'Runtime is required'),
  packageManager: z.string().optional(),
  lockfileHash: z.string().optional(),
  setupVersion: z.number().int().min(1).default(1),
  createdAt: z.date().optional(),
  updatedAt: z.date().optional(),
})

export const selectSandboxProfileSchema = z.object({
  id: z.string(),
  profileKey: z.string(),
  scopeType: z.string(),
  scopeOwnerId: z.string().nullable(),
  repoUrl: z.string().nullable(),
  runtime: z.string(),
  packageManager: z.string().nullable(),
  lockfileHash: z.string().nullable(),
  setupVersion: z.number(),
  createdAt: z.date(),
  updatedAt: z.date(),
})

export type SandboxProfile = z.infer<typeof selectSandboxProfileSchema>
export type InsertSandboxProfile = z.infer<typeof insertSandboxProfileSchema>

// ============================================================
// Sandbox Snapshots table — Vercel snapshot registry
// Phase 0 scaffold: schema only; consumers added in Phase 1+
// ============================================================
// status values: 'creating' | 'ready' | 'failed' | 'expired'
//   'creating' — snapshot creation in progress
//   'ready'    — snapshot is available for restore
//   'failed'   — snapshot creation failed; do not use
//   'expired'  — snapshot TTL exceeded or explicitly expired
// validationState values: 'untested' | 'valid' | 'invalid'
//   'untested' — snapshot has never been validation-restored
//   'valid'    — at least one successful restore confirmed
//   'invalid'  — restore failed; snapshot should not be used
export const sandboxSnapshots = pgTable(
  'sandbox_snapshots',
  {
    id: text('id')
      .primaryKey()
      .$defaultFn(() => createId()),
    // Foreign key to sandbox_profiles — cascade delete when profile is removed
    profileId: text('profile_id')
      .notNull()
      .references(() => sandboxProfiles.id, { onDelete: 'cascade' }),
    // Vercel SDK snapshot id
    snapshotId: text('snapshot_id').notNull(),
    // status values: 'creating' | 'ready' | 'failed' | 'expired' (see table comment above)
    status: text('status').notNull(),
    createdFromRuntime: text('created_from_runtime').notNull(),
    // Vercel default TTL is 30 days; null means unknown or no expiration
    expiresAt: timestamp('expires_at'),
    lastUsedAt: timestamp('last_used_at'),
    restoreCount: integer('restore_count').notNull().default(0),
    // Wall-clock milliseconds from create request to snapshot ready
    buildDurationMs: integer('build_duration_ms'),
    // Milliseconds for the most recent warm restore
    restoreDurationMs: integer('restore_duration_ms'),
    // validationState values: 'untested' | 'valid' | 'invalid' (see table comment above)
    validationState: text('validation_state').notNull().default('untested'),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
  },
  (table) => ({
    // Index for queries scoped to a profile
    profileIdIdx: index('sandbox_snapshots_profile_id_idx').on(table.profileId),
    // Composite index for "find most recent valid snapshot" queries
    profileStatusExpiresIdx: index('sandbox_snapshots_profile_status_expires_idx').on(
      table.profileId,
      table.status,
      table.expiresAt,
    ),
    // Defensive index on Vercel snapshot id (not unique — guard against SDK quirks)
    snapshotIdIdx: index('sandbox_snapshots_snapshot_id_idx').on(table.snapshotId),
  }),
)

export const insertSandboxSnapshotSchema = z.object({
  id: z.string().optional(),
  profileId: z.string().min(1, 'Profile ID is required'),
  snapshotId: z.string().min(1, 'Snapshot ID is required'),
  status: z.string().min(1, 'Status is required'),
  createdFromRuntime: z.string().min(1, 'Runtime is required'),
  expiresAt: z.date().optional(),
  lastUsedAt: z.date().optional(),
  restoreCount: z.number().int().min(0).default(0),
  buildDurationMs: z.number().int().optional(),
  restoreDurationMs: z.number().int().optional(),
  validationState: z.string().default('untested'),
  createdAt: z.date().optional(),
  updatedAt: z.date().optional(),
})

export const selectSandboxSnapshotSchema = z.object({
  id: z.string(),
  profileId: z.string(),
  snapshotId: z.string(),
  status: z.string(),
  createdFromRuntime: z.string(),
  expiresAt: z.date().nullable(),
  lastUsedAt: z.date().nullable(),
  restoreCount: z.number(),
  buildDurationMs: z.number().nullable(),
  restoreDurationMs: z.number().nullable(),
  validationState: z.string(),
  createdAt: z.date(),
  updatedAt: z.date(),
})

export type SandboxSnapshot = z.infer<typeof selectSandboxSnapshotSchema>
export type InsertSandboxSnapshot = z.infer<typeof insertSandboxSnapshotSchema>

// ============================================================
// Sandbox Workspaces table — named persistent sandbox registry
// Phase 0 scaffold: schema only; consumers added in Phase 2+
// ============================================================
// mode values: 'ephemeral' | 'persistent'
//   'ephemeral'  — sandbox is stopped after task completes (default)
//   'persistent' — sandbox is kept alive for follow-up interactions
// status values: 'active' | 'idle' | 'expired' | 'failed'
//   'active'  — sandbox is currently running and responsive
//   'idle'    — sandbox exists but has no active task
//   'expired' — sandbox TTL exceeded or was shut down
//   'failed'  — sandbox became unhealthy and cannot be resumed
export const sandboxWorkspaces = pgTable(
  'sandbox_workspaces',
  {
    id: text('id')
      .primaryKey()
      .$defaultFn(() => createId()),
    // Sandbox.get({ name }) key — unique stable identifier for this workspace
    workspaceName: text('workspace_name').notNull().unique(),
    // Most recent task using this workspace; SET NULL on task delete
    taskId: text('task_id').references(() => tasks.id, { onDelete: 'set null' }),
    // Owner — matches tasks.userId type (text)
    userId: text('user_id').notNull(),
    repoUrl: text('repo_url').notNull(),
    // Current live sandbox id if one is active; null when idle/expired
    sandboxId: text('sandbox_id'),
    // Most recent snapshot id associated with this workspace
    currentSnapshotId: text('current_snapshot_id'),
    // mode values: 'ephemeral' | 'persistent' (see table comment above)
    mode: text('mode').notNull(),
    // status values: 'active' | 'idle' | 'expired' | 'failed' (see table comment above)
    status: text('status').notNull(),
    lastSeenAt: timestamp('last_seen_at'),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
  },
  (table) => ({
    // Enforce uniqueness on the workspace name (Sandbox.get({ name }) key)
    workspaceNameUnique: uniqueIndex('sandbox_workspaces_workspace_name_idx').on(table.workspaceName),
    // Composite index for "does a workspace exist for this user+repo" queries
    userRepoIdx: index('sandbox_workspaces_user_repo_idx').on(table.userId, table.repoUrl),
  }),
)

export const insertSandboxWorkspaceSchema = z.object({
  id: z.string().optional(),
  workspaceName: z.string().min(1, 'Workspace name is required'),
  taskId: z.string().optional(),
  userId: z.string().min(1, 'User ID is required'),
  repoUrl: z.string().min(1, 'Repo URL is required'),
  sandboxId: z.string().optional(),
  currentSnapshotId: z.string().optional(),
  mode: z.string().min(1, 'Mode is required'),
  status: z.string().min(1, 'Status is required'),
  lastSeenAt: z.date().optional(),
  createdAt: z.date().optional(),
  updatedAt: z.date().optional(),
})

export const selectSandboxWorkspaceSchema = z.object({
  id: z.string(),
  workspaceName: z.string(),
  taskId: z.string().nullable(),
  userId: z.string(),
  repoUrl: z.string(),
  sandboxId: z.string().nullable(),
  currentSnapshotId: z.string().nullable(),
  mode: z.string(),
  status: z.string(),
  lastSeenAt: z.date().nullable(),
  createdAt: z.date(),
  updatedAt: z.date(),
})

export type SandboxWorkspace = z.infer<typeof selectSandboxWorkspaceSchema>
export type InsertSandboxWorkspace = z.infer<typeof insertSandboxWorkspaceSchema>

// Keep legacy export for backwards compatibility during migration
export const userConnections = accounts
export type UserConnection = Account
export type InsertUserConnection = InsertAccount
