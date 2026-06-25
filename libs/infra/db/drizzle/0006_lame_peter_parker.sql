ALTER TYPE "public"."audit_event_type" ADD VALUE 'agent';--> statement-breakpoint
ALTER TABLE "audit_logs" ADD COLUMN "actor_client_id" varchar(255);--> statement-breakpoint
ALTER TABLE "audit_logs" ADD COLUMN "delegation_chain" jsonb;--> statement-breakpoint
ALTER TABLE "audit_logs" ADD COLUMN "scope_mode" "agent_mode";--> statement-breakpoint
CREATE INDEX "idx_audit_logs_actor_client_id" ON "audit_logs" USING btree ("actor_client_id","created_at") WHERE "audit_logs"."actor_client_id" IS NOT NULL;