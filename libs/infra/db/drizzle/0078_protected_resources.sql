-- #1087: the protected resources a realm registers (RFC 8707, RFC 9728), the
-- scopes each defines with their consent texts by locale, and the clients
-- that may ask for them: every client of the realm (`any_client`) or the
-- listed `client_id`s. A scope a registered resource defines is granted only
-- to an authorization request that names the resource, and then to any
-- client the resource is open to, whatever the client's own scope list holds.
--
-- A new, empty table: nothing is rewritten, and a release before this one
-- never names it, so it is safe during a rolling upgrade. A node of such a
-- release grants by the client's own scope list alone while the upgrade
-- runs. Forward-only.
CREATE TABLE "protected_resources" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"realm_id" uuid NOT NULL,
	"resource" varchar(2048) NOT NULL,
	"scopes" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"any_client" boolean DEFAULT false NOT NULL,
	"client_ids" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"version" integer DEFAULT 1 NOT NULL,
	"created_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	"updated_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	CONSTRAINT "protected_resources_realm_resource" UNIQUE("realm_id","resource"),
	CONSTRAINT "protected_resources_resource_form" CHECK ("protected_resources"."resource" <> '' AND strpos("protected_resources"."resource", '#') = 0),
	CONSTRAINT "protected_resources_scopes_array" CHECK (jsonb_typeof("protected_resources"."scopes") = 'array'),
	CONSTRAINT "protected_resources_client_ids_array" CHECK (jsonb_typeof("protected_resources"."client_ids") = 'array'),
	CONSTRAINT "protected_resources_any_client_lists_none" CHECK (NOT "protected_resources"."any_client" OR "protected_resources"."client_ids" = '[]'::jsonb),
	CONSTRAINT "protected_resources_version_positive" CHECK ("protected_resources"."version" > 0)
);
--> statement-breakpoint
ALTER TABLE "protected_resources" ADD CONSTRAINT "protected_resources_realm_id_realms_id_fk" FOREIGN KEY ("realm_id") REFERENCES "public"."realms"("id") ON DELETE cascade ON UPDATE no action;