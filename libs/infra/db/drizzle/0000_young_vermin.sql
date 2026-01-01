-- QAuth requires PostgreSQL 18+ for native uuidv7() support
-- uuidv7() provides time-ordered UUIDs for better B-tree index performance
-- No extension needed - uuidv7() is built-in starting from PostgreSQL 18
-- If you're using PostgreSQL < 18, please upgrade to PostgreSQL 18 or later

--> statement-breakpoint
CREATE TYPE "public"."audit_event_type" AS ENUM('auth', 'token', 'client', 'security', 'user', 'realm');--> statement-breakpoint
CREATE TYPE "public"."code_challenge_method" AS ENUM('S256');--> statement-breakpoint
CREATE TYPE "public"."grant_type" AS ENUM('authorization_code', 'refresh_token', 'client_credentials');--> statement-breakpoint
CREATE TYPE "public"."response_type" AS ENUM('code');--> statement-breakpoint
CREATE TYPE "public"."ssl_required" AS ENUM('none', 'external', 'all');--> statement-breakpoint
CREATE TYPE "public"."token_endpoint_auth_method" AS ENUM('client_secret_post', 'client_secret_basic', 'private_key_jwt', 'none');--> statement-breakpoint
CREATE TABLE "audit_logs" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"user_id" uuid,
	"oauth_client_id" uuid,
	"event" varchar(100) NOT NULL,
	"event_type" "audit_event_type" NOT NULL,
	"success" boolean DEFAULT true NOT NULL,
	"ip_address" varchar(45),
	"user_agent" text,
	"metadata" jsonb,
	"created_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL
);
--> statement-breakpoint
CREATE TABLE "oauth_clients" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"realm_id" uuid NOT NULL,
	"client_id" varchar(255) NOT NULL,
	"client_secret_hash" text NOT NULL,
	"name" varchar(255) NOT NULL,
	"description" text,
	"redirect_uris" jsonb NOT NULL,
	"scopes" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"require_pkce" boolean DEFAULT true NOT NULL,
	"token_endpoint_auth_method" "token_endpoint_auth_method" DEFAULT 'client_secret_post' NOT NULL,
	"grant_types" jsonb DEFAULT '["authorization_code","refresh_token"]'::jsonb NOT NULL,
	"response_types" jsonb DEFAULT '["code"]'::jsonb NOT NULL,
	"developer_id" uuid,
	"metadata" jsonb,
	"created_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	"updated_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	"last_used_at" bigint
);
--> statement-breakpoint
CREATE TABLE "realms" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"name" varchar(255) NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"access_token_lifespan" bigint DEFAULT 900,
	"refresh_token_lifespan" bigint DEFAULT 604800,
	"ssl_required" "ssl_required" DEFAULT 'external',
	"verify_email" boolean DEFAULT true NOT NULL,
	"registration_allowed" boolean DEFAULT false NOT NULL,
	"login_with_email_allowed" boolean DEFAULT true NOT NULL,
	"duplicate_emails_allowed" boolean DEFAULT false NOT NULL,
	"password_policy" jsonb,
	"sso_idle_timeout" bigint,
	"sso_max_lifespan" bigint,
	"revoke_refresh_token" boolean DEFAULT false NOT NULL,
	"refresh_token_max_reuse" bigint DEFAULT 0,
	"default_locale" varchar(10),
	"supported_locales" jsonb DEFAULT '[]'::jsonb,
	"metadata" jsonb,
	"created_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	"updated_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	CONSTRAINT "realms_name_unique" UNIQUE("name")
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"realm_id" uuid NOT NULL,
	"email" varchar(255) NOT NULL,
	"email_normalized" varchar(255) NOT NULL,
	"password_hash" text NOT NULL,
	"email_verified" boolean DEFAULT false NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"first_name" varchar(255),
	"last_name" varchar(255),
	"metadata" jsonb,
	"created_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	"updated_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	"last_login_at" bigint,
	"email_verified_at" bigint
);
--> statement-breakpoint
CREATE TABLE "roles" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"realm_id" uuid NOT NULL,
	"name" varchar(255) NOT NULL,
	"description" text,
	"oauth_client_id" uuid,
	"enabled" boolean DEFAULT true NOT NULL,
	"metadata" jsonb,
	"created_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	"updated_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL
);
--> statement-breakpoint
CREATE TABLE "user_roles" (
	"user_id" uuid NOT NULL,
	"role_id" uuid NOT NULL,
	"assigned_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	"assigned_by" uuid,
	CONSTRAINT "user_roles_pk" PRIMARY KEY("user_id","role_id")
);
--> statement-breakpoint
CREATE TABLE "sessions" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"user_id" uuid NOT NULL,
	"oauth_client_id" uuid,
	"access_token_hash" text,
	"refresh_token_hash" text,
	"ip_address" varchar(45),
	"user_agent" text,
	"expires_at" bigint NOT NULL,
	"revoked" boolean DEFAULT false NOT NULL,
	"revoked_at" bigint,
	"created_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	"last_activity_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL
);
--> statement-breakpoint
CREATE TABLE "authorization_codes" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"code" varchar(255) NOT NULL,
	"oauth_client_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"redirect_uri" text NOT NULL,
	"code_challenge" text NOT NULL,
	"code_challenge_method" "code_challenge_method" DEFAULT 'S256' NOT NULL,
	"nonce" varchar(255),
	"scopes" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"state" varchar(255),
	"expires_at" bigint NOT NULL,
	"used" boolean DEFAULT false NOT NULL,
	"used_at" bigint,
	"created_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	CONSTRAINT "authorization_codes_code_unique" UNIQUE("code")
);
--> statement-breakpoint
CREATE TABLE "email_verification_tokens" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"token_hash" varchar(64) NOT NULL,
	"user_id" uuid NOT NULL,
	"expires_at" bigint NOT NULL,
	"used" boolean DEFAULT false NOT NULL,
	"used_at" bigint,
	"created_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	CONSTRAINT "email_verification_tokens_token_hash_unique" UNIQUE("token_hash")
);
--> statement-breakpoint
CREATE TABLE "refresh_tokens" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"token_hash" varchar(64) NOT NULL,
	"user_id" uuid NOT NULL,
	"oauth_client_id" uuid NOT NULL,
	"scopes" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"expires_at" bigint NOT NULL,
	"revoked" boolean DEFAULT false NOT NULL,
	"revoked_at" bigint,
	"revoked_reason" varchar(255),
	"previous_token_hash" varchar(64),
	"created_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	"last_used_at" bigint,
	CONSTRAINT "refresh_tokens_token_hash_unique" UNIQUE("token_hash")
);
--> statement-breakpoint
ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_oauth_client_id_oauth_clients_id_fk" FOREIGN KEY ("oauth_client_id") REFERENCES "public"."oauth_clients"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "oauth_clients" ADD CONSTRAINT "oauth_clients_realm_id_realms_id_fk" FOREIGN KEY ("realm_id") REFERENCES "public"."realms"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "oauth_clients" ADD CONSTRAINT "oauth_clients_developer_id_users_id_fk" FOREIGN KEY ("developer_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "users" ADD CONSTRAINT "users_realm_id_realms_id_fk" FOREIGN KEY ("realm_id") REFERENCES "public"."realms"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "roles" ADD CONSTRAINT "roles_realm_id_realms_id_fk" FOREIGN KEY ("realm_id") REFERENCES "public"."realms"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "roles" ADD CONSTRAINT "roles_oauth_client_id_oauth_clients_id_fk" FOREIGN KEY ("oauth_client_id") REFERENCES "public"."oauth_clients"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_roles" ADD CONSTRAINT "user_roles_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_roles" ADD CONSTRAINT "user_roles_role_id_roles_id_fk" FOREIGN KEY ("role_id") REFERENCES "public"."roles"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_roles" ADD CONSTRAINT "user_roles_assigned_by_users_id_fk" FOREIGN KEY ("assigned_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_oauth_client_id_oauth_clients_id_fk" FOREIGN KEY ("oauth_client_id") REFERENCES "public"."oauth_clients"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "authorization_codes" ADD CONSTRAINT "authorization_codes_oauth_client_id_oauth_clients_id_fk" FOREIGN KEY ("oauth_client_id") REFERENCES "public"."oauth_clients"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "authorization_codes" ADD CONSTRAINT "authorization_codes_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "email_verification_tokens" ADD CONSTRAINT "email_verification_tokens_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_oauth_client_id_oauth_clients_id_fk" FOREIGN KEY ("oauth_client_id") REFERENCES "public"."oauth_clients"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_audit_logs_user_id" ON "audit_logs" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "idx_audit_logs_oauth_client_id" ON "audit_logs" USING btree ("oauth_client_id");--> statement-breakpoint
CREATE INDEX "idx_audit_logs_event_type" ON "audit_logs" USING btree ("event_type");--> statement-breakpoint
CREATE INDEX "idx_audit_logs_event" ON "audit_logs" USING btree ("event");--> statement-breakpoint
CREATE INDEX "idx_audit_logs_created_at" ON "audit_logs" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX "idx_audit_logs_user_event" ON "audit_logs" USING btree ("user_id","event","created_at");--> statement-breakpoint
CREATE INDEX "idx_audit_logs_failed" ON "audit_logs" USING btree ("event","created_at") WHERE "audit_logs"."success" = false;--> statement-breakpoint
CREATE INDEX "idx_audit_logs_ip_address" ON "audit_logs" USING btree ("ip_address");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_oauth_clients_realm_client_id_unique" ON "oauth_clients" USING btree ("realm_id","client_id");--> statement-breakpoint
CREATE INDEX "idx_oauth_clients_client_id" ON "oauth_clients" USING btree ("client_id");--> statement-breakpoint
CREATE INDEX "idx_oauth_clients_realm_id" ON "oauth_clients" USING btree ("realm_id");--> statement-breakpoint
CREATE INDEX "idx_oauth_clients_developer_id" ON "oauth_clients" USING btree ("developer_id");--> statement-breakpoint
CREATE INDEX "idx_oauth_clients_enabled" ON "oauth_clients" USING btree ("enabled") WHERE "oauth_clients"."enabled" = true;--> statement-breakpoint
CREATE INDEX "idx_oauth_clients_realm_client_id_enabled" ON "oauth_clients" USING btree ("realm_id","client_id","enabled");--> statement-breakpoint
CREATE INDEX "idx_realms_enabled" ON "realms" USING btree ("enabled") WHERE "realms"."enabled" = true;--> statement-breakpoint
CREATE UNIQUE INDEX "idx_users_realm_email_normalized_unique" ON "users" USING btree ("realm_id","email_normalized");--> statement-breakpoint
CREATE INDEX "idx_users_email" ON "users" USING btree ("email");--> statement-breakpoint
CREATE INDEX "idx_users_realm_id" ON "users" USING btree ("realm_id");--> statement-breakpoint
CREATE INDEX "idx_users_enabled" ON "users" USING btree ("enabled") WHERE "users"."enabled" = true;--> statement-breakpoint
CREATE INDEX "idx_users_realm_email_enabled" ON "users" USING btree ("realm_id","email_normalized","enabled");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_roles_realm_name_unique" ON "roles" USING btree ("realm_id","name","oauth_client_id");--> statement-breakpoint
CREATE INDEX "idx_roles_name" ON "roles" USING btree ("name");--> statement-breakpoint
CREATE INDEX "idx_roles_realm_id" ON "roles" USING btree ("realm_id");--> statement-breakpoint
CREATE INDEX "idx_roles_oauth_client_id" ON "roles" USING btree ("oauth_client_id");--> statement-breakpoint
CREATE INDEX "idx_user_roles_user_id" ON "user_roles" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "idx_user_roles_role_id" ON "user_roles" USING btree ("role_id");--> statement-breakpoint
CREATE INDEX "idx_sessions_user_id" ON "sessions" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "idx_sessions_active" ON "sessions" USING btree ("user_id","expires_at") WHERE "sessions"."revoked" = false;--> statement-breakpoint
CREATE INDEX "idx_sessions_expires_at" ON "sessions" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "idx_sessions_access_token_hash" ON "sessions" USING btree ("access_token_hash");--> statement-breakpoint
CREATE INDEX "idx_sessions_oauth_client_id" ON "sessions" USING btree ("oauth_client_id");--> statement-breakpoint
CREATE INDEX "idx_authorization_codes_active" ON "authorization_codes" USING btree ("code","expires_at") WHERE "authorization_codes"."used" = false;--> statement-breakpoint
CREATE INDEX "idx_authorization_codes_expires_at" ON "authorization_codes" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "idx_authorization_codes_user_id" ON "authorization_codes" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "idx_authorization_codes_oauth_client_id" ON "authorization_codes" USING btree ("oauth_client_id");--> statement-breakpoint
CREATE INDEX "idx_email_verification_tokens_user_id" ON "email_verification_tokens" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "idx_email_verification_tokens_active" ON "email_verification_tokens" USING btree ("token_hash","expires_at") WHERE "email_verification_tokens"."used" = false;--> statement-breakpoint
CREATE INDEX "idx_email_verification_tokens_expires_at" ON "email_verification_tokens" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "idx_refresh_tokens_active" ON "refresh_tokens" USING btree ("token_hash","expires_at") WHERE "refresh_tokens"."revoked" = false;--> statement-breakpoint
CREATE INDEX "idx_refresh_tokens_expires_at" ON "refresh_tokens" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "idx_refresh_tokens_user_id" ON "refresh_tokens" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "idx_refresh_tokens_oauth_client_id" ON "refresh_tokens" USING btree ("oauth_client_id");--> statement-breakpoint
CREATE INDEX "idx_refresh_tokens_user_active" ON "refresh_tokens" USING btree ("user_id","expires_at") WHERE "refresh_tokens"."revoked" = false;