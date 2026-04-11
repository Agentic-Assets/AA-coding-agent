CREATE TABLE "sandbox_profiles" (
	"id" text PRIMARY KEY NOT NULL,
	"profile_key" text NOT NULL,
	"scope_type" text NOT NULL,
	"scope_owner_id" text,
	"repo_url" text,
	"runtime" text NOT NULL,
	"package_manager" text,
	"lockfile_hash" text,
	"setup_version" integer DEFAULT 1 NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "sandbox_profiles_profile_key_unique" UNIQUE("profile_key")
);
--> statement-breakpoint
CREATE TABLE "sandbox_snapshots" (
	"id" text PRIMARY KEY NOT NULL,
	"profile_id" text NOT NULL,
	"snapshot_id" text NOT NULL,
	"status" text NOT NULL,
	"created_from_runtime" text NOT NULL,
	"expires_at" timestamp,
	"last_used_at" timestamp,
	"restore_count" integer DEFAULT 0 NOT NULL,
	"build_duration_ms" integer,
	"restore_duration_ms" integer,
	"validation_state" text DEFAULT 'untested' NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "sandbox_workspaces" (
	"id" text PRIMARY KEY NOT NULL,
	"workspace_name" text NOT NULL,
	"task_id" text,
	"user_id" text NOT NULL,
	"repo_url" text NOT NULL,
	"sandbox_id" text,
	"current_snapshot_id" text,
	"mode" text NOT NULL,
	"status" text NOT NULL,
	"last_seen_at" timestamp,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "sandbox_workspaces_workspace_name_unique" UNIQUE("workspace_name")
);
--> statement-breakpoint
ALTER TABLE "tasks" ADD COLUMN "heartbeat_extension_count" integer DEFAULT 0;--> statement-breakpoint
ALTER TABLE "tasks" ADD COLUMN "sandbox_mode" text;--> statement-breakpoint
ALTER TABLE "tasks" ADD COLUMN "setup_profile_key" text;--> statement-breakpoint
ALTER TABLE "tasks" ADD COLUMN "snapshot_id" text;--> statement-breakpoint
ALTER TABLE "tasks" ADD COLUMN "persistent_workspace_name" text;--> statement-breakpoint
ALTER TABLE "sandbox_snapshots" ADD CONSTRAINT "sandbox_snapshots_profile_id_sandbox_profiles_id_fk" FOREIGN KEY ("profile_id") REFERENCES "public"."sandbox_profiles"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sandbox_workspaces" ADD CONSTRAINT "sandbox_workspaces_task_id_tasks_id_fk" FOREIGN KEY ("task_id") REFERENCES "public"."tasks"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "sandbox_profiles_profile_key_idx" ON "sandbox_profiles" USING btree ("profile_key");--> statement-breakpoint
CREATE INDEX "sandbox_profiles_scope_lookup_idx" ON "sandbox_profiles" USING btree ("scope_type","scope_owner_id","repo_url");--> statement-breakpoint
CREATE INDEX "sandbox_snapshots_profile_id_idx" ON "sandbox_snapshots" USING btree ("profile_id");--> statement-breakpoint
CREATE INDEX "sandbox_snapshots_profile_status_expires_idx" ON "sandbox_snapshots" USING btree ("profile_id","status","expires_at");--> statement-breakpoint
CREATE INDEX "sandbox_snapshots_snapshot_id_idx" ON "sandbox_snapshots" USING btree ("snapshot_id");--> statement-breakpoint
CREATE UNIQUE INDEX "sandbox_workspaces_workspace_name_idx" ON "sandbox_workspaces" USING btree ("workspace_name");--> statement-breakpoint
CREATE INDEX "sandbox_workspaces_user_repo_idx" ON "sandbox_workspaces" USING btree ("user_id","repo_url");