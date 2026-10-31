-- #512 (ADR-019 Decision 7): approval requests for security operations. One
-- new table, and no change to a row of any other.
--
-- Locks first, in the order the writers of both referenced tables take them,
-- as 0043 does: a realm's deletion takes `realms` and then cascades into
-- `users`, while a user's insert only key-shares its realm, which SHARE ROW
-- EXCLUSIVE lets through. The foreign keys below would take `realms`, then
-- `users`, then `realms` again; taking both up front keeps a realm deletion
-- that started while the migration waited from deadlocking with it. SHARE ROW
-- EXCLUSIVE is what ADD FOREIGN KEY takes on the referenced table: reads go
-- on, writes wait for the runner's commit.
LOCK TABLE "realms" IN SHARE ROW EXCLUSIVE MODE;--> statement-breakpoint
LOCK TABLE "users" IN SHARE ROW EXCLUSIVE MODE;--> statement-breakpoint
CREATE TABLE "admin_approvals" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"realm_id" uuid NOT NULL,
	"requester_kind" varchar(32) NOT NULL,
	"requester_realm_id" uuid NOT NULL,
	"requester_id" uuid NOT NULL,
	"operation_id" varchar(128) NOT NULL,
	"canonical_request" jsonb NOT NULL,
	"request_hash" "bytea" NOT NULL,
	"op_hash" "bytea" NOT NULL,
	"nonce" "bytea" NOT NULL,
	"reason" varchar(500),
	"classification" jsonb NOT NULL,
	"approvals_required" smallint NOT NULL,
	"approvals" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"status" varchar(16) DEFAULT 'pending' NOT NULL,
	"created_at" bigint NOT NULL,
	"expires_at" bigint NOT NULL,
	"used_at" bigint,
	CONSTRAINT "admin_approvals_requester_kind" CHECK ("admin_approvals"."requester_kind" in ('human', 'service_account')),
	CONSTRAINT "admin_approvals_status" CHECK ("admin_approvals"."status" in ('pending', 'approved', 'denied', 'cancelled', 'consumed')),
	CONSTRAINT "admin_approvals_operation_id_not_empty" CHECK ("admin_approvals"."operation_id" <> ''),
	CONSTRAINT "admin_approvals_canonical_request_object" CHECK (jsonb_typeof("admin_approvals"."canonical_request") = 'object'),
	CONSTRAINT "admin_approvals_request_hash_sha256" CHECK (octet_length("admin_approvals"."request_hash") = 32),
	CONSTRAINT "admin_approvals_op_hash_sha256" CHECK (octet_length("admin_approvals"."op_hash") = 32),
	CONSTRAINT "admin_approvals_nonce_length" CHECK (octet_length("admin_approvals"."nonce") = 32),
	CONSTRAINT "admin_approvals_reason_not_empty" CHECK ("admin_approvals"."reason" is null or "admin_approvals"."reason" <> ''),
	CONSTRAINT "admin_approvals_classification_object" CHECK (jsonb_typeof("admin_approvals"."classification") = 'object'),
	CONSTRAINT "admin_approvals_required_range" CHECK ("admin_approvals"."approvals_required" between 1 and 2),
	CONSTRAINT "admin_approvals_approvals_array" CHECK (jsonb_typeof("admin_approvals"."approvals") = 'array' and jsonb_array_length("admin_approvals"."approvals") <= "admin_approvals"."approvals_required"),
	CONSTRAINT "admin_approvals_status_matches_approvals" CHECK (("admin_approvals"."status" not in ('approved', 'consumed') or jsonb_array_length("admin_approvals"."approvals") = "admin_approvals"."approvals_required") and ("admin_approvals"."status" <> 'pending' or jsonb_array_length("admin_approvals"."approvals") < "admin_approvals"."approvals_required")),
	CONSTRAINT "admin_approvals_expires_after_created" CHECK ("admin_approvals"."expires_at" > "admin_approvals"."created_at"),
	CONSTRAINT "admin_approvals_used_exactly_when_consumed" CHECK (("admin_approvals"."status" = 'consumed') = ("admin_approvals"."used_at" is not null))
);
--> statement-breakpoint
ALTER TABLE "admin_approvals" ADD CONSTRAINT "admin_approvals_realm_id_realms_id_fk" FOREIGN KEY ("realm_id") REFERENCES "public"."realms"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "admin_approvals" ADD CONSTRAINT "admin_approvals_requester_realm_id_realms_id_fk" FOREIGN KEY ("requester_realm_id") REFERENCES "public"."realms"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "admin_approvals" ADD CONSTRAINT "admin_approvals_requester_id_users_id_fk" FOREIGN KEY ("requester_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_admin_approvals_realm_created" ON "admin_approvals" USING btree ("realm_id","created_at");--> statement-breakpoint
CREATE INDEX "idx_admin_approvals_requester" ON "admin_approvals" USING btree ("requester_id");
