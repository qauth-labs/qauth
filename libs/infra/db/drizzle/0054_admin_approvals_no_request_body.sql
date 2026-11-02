-- #901: an approval keeps no request body, and no hash of the request without
-- its nonce. The body of a security operation may hold a secret (an SMTP
-- password, an upstream client secret, key material), and `request_hash`, the
-- SHA-256 of the whole canonical request, let anyone with a copy of the table
-- test a guessed body against it offline. From here on the row keeps the
-- method, the path parameters and the query in columns of their own, and
-- `display`, what an approver is shown, rendered when the approval is filed.
-- The retried call is bound through `op_hash` alone, computed with the stored
-- nonce, and a closed or expired approval's nonce is overwritten.
--
-- The status `expired` is stored from here on: the expiry sweep marks an open
-- approval past its expiry, and overwrites its nonce.
ALTER TABLE "admin_approvals" DROP CONSTRAINT "admin_approvals_status";--> statement-breakpoint
ALTER TABLE "admin_approvals" ADD COLUMN "method" varchar(16);--> statement-breakpoint
ALTER TABLE "admin_approvals" ADD COLUMN "params" jsonb;--> statement-breakpoint
ALTER TABLE "admin_approvals" ADD COLUMN "query" jsonb;--> statement-breakpoint
ALTER TABLE "admin_approvals" ADD COLUMN "display" jsonb;--> statement-breakpoint
-- Each approval filed before this migration: its method, path parameters and
-- query move to their columns, and in the same row version its stored request
-- is emptied and its `request_hash` and nonce are overwritten with random
-- bytes, so the row the dropped columns stay in (DROP COLUMN only hides them)
-- holds neither the body nor a hash of it. It has no display, which only the
-- operation's renderer can make, so one still open is retired as `expired`
-- and its requester files it again: no approver could see what it asks.
UPDATE "admin_approvals" SET
	"method" = "canonical_request" ->> 'method',
	"params" = coalesce("canonical_request" -> 'params', '{}'::jsonb),
	"query" = coalesce("canonical_request" -> 'query', '{}'::jsonb),
	"canonical_request" = '{}'::jsonb,
	"request_hash" = sha256(convert_to(gen_random_uuid()::text || gen_random_uuid()::text, 'UTF8')),
	"nonce" = sha256(convert_to(gen_random_uuid()::text || gen_random_uuid()::text, 'UTF8')),
	"status" = CASE WHEN "status" IN ('pending', 'approved') THEN 'expired' ELSE "status" END;--> statement-breakpoint
ALTER TABLE "admin_approvals" ALTER COLUMN "method" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "admin_approvals" ALTER COLUMN "params" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "admin_approvals" ALTER COLUMN "query" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "admin_approvals" DROP CONSTRAINT "admin_approvals_canonical_request_object";--> statement-breakpoint
ALTER TABLE "admin_approvals" DROP CONSTRAINT "admin_approvals_request_hash_sha256";--> statement-breakpoint
ALTER TABLE "admin_approvals" DROP COLUMN "canonical_request";--> statement-breakpoint
ALTER TABLE "admin_approvals" DROP COLUMN "request_hash";--> statement-breakpoint
CREATE INDEX "idx_admin_approvals_open_expiry" ON "admin_approvals" USING btree ("expires_at") WHERE "admin_approvals"."status" in ('pending', 'approved');--> statement-breakpoint
ALTER TABLE "admin_approvals" ADD CONSTRAINT "admin_approvals_method_not_empty" CHECK ("admin_approvals"."method" <> '');--> statement-breakpoint
ALTER TABLE "admin_approvals" ADD CONSTRAINT "admin_approvals_params_object" CHECK (jsonb_typeof("admin_approvals"."params") = 'object');--> statement-breakpoint
ALTER TABLE "admin_approvals" ADD CONSTRAINT "admin_approvals_query_object" CHECK (jsonb_typeof("admin_approvals"."query") = 'object');--> statement-breakpoint
ALTER TABLE "admin_approvals" ADD CONSTRAINT "admin_approvals_display_object" CHECK ("admin_approvals"."display" is null or jsonb_typeof("admin_approvals"."display") = 'object');--> statement-breakpoint
ALTER TABLE "admin_approvals" ADD CONSTRAINT "admin_approvals_open_has_display" CHECK ("admin_approvals"."status" not in ('pending', 'approved') or "admin_approvals"."display" is not null);--> statement-breakpoint
ALTER TABLE "admin_approvals" ADD CONSTRAINT "admin_approvals_status" CHECK ("admin_approvals"."status" in ('pending', 'approved', 'denied', 'cancelled', 'consumed', 'expired'));
