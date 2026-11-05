-- #639 (ADR-020): the generic upstream OpenID Connect providers of each realm,
-- one row per provider: its AuthMethod type (`oidc_` plus a lower-case alias),
-- how the sign-in page lists it, whether it is on, whether an account created
-- through it counts as verified, and its stored config, whose client secret is
-- sealed with the realm's data_at_rest key. A new table that no earlier
-- release reads or writes, so the previous release keeps working on the new
-- schema during a rolling upgrade. Forward-only: nothing is rewritten.
--
-- The CHECKs hold the stored forms: a type under the federation contract's
-- UPSTREAM_OIDC_TYPE_PATTERN (an alias holds no `:` or `/`, so it can never
-- equal an ID-JAG type, `oidc_<issuer URL>`), a display name of 1 to 64
-- characters, and a config that is a JSON object. One provider per type in a
-- realm; the unique index's leading realm_id also serves the realm foreign
-- key's cascade and the listing of a realm's providers.
CREATE TABLE "realm_upstream_providers" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"realm_id" uuid NOT NULL,
	"type" text NOT NULL,
	"display_name" text NOT NULL,
	"display_order" integer DEFAULT 0 NOT NULL,
	"hidden" boolean DEFAULT false NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"marks_verified" boolean DEFAULT true NOT NULL,
	"config" jsonb NOT NULL,
	"created_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	"updated_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	CONSTRAINT "realm_upstream_providers_type_form" CHECK ("realm_upstream_providers"."type" ~ '^oidc_[a-z0-9][a-z0-9_]{0,57}$'),
	CONSTRAINT "realm_upstream_providers_display_name_length" CHECK (char_length("realm_upstream_providers"."display_name") BETWEEN 1 AND 64),
	CONSTRAINT "realm_upstream_providers_config_object" CHECK (jsonb_typeof("realm_upstream_providers"."config") = 'object')
);
--> statement-breakpoint
ALTER TABLE "realm_upstream_providers" ADD CONSTRAINT "realm_upstream_providers_realm_id_realms_id_fk" FOREIGN KEY ("realm_id") REFERENCES "public"."realms"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "idx_realm_upstream_providers_realm_type_unique" ON "realm_upstream_providers" USING btree ("realm_id","type");