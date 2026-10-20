CREATE TYPE "public"."realm_key_status" AS ENUM('next', 'active', 'retired', 'compromised');--> statement-breakpoint
CREATE TABLE "realm_keys" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"realm_id" uuid NOT NULL,
	"purpose" varchar(64) NOT NULL,
	"scope_id" varchar(255),
	"algorithm" varchar(32) NOT NULL,
	"kid" varchar(255) NOT NULL,
	"status" realm_key_status NOT NULL,
	"pair_id" uuid,
	"ciphertext" "bytea" NOT NULL,
	"iv" "bytea" NOT NULL,
	"wrapped_dek" "bytea" NOT NULL,
	"kek_ref" text NOT NULL,
	"aad_version" smallint NOT NULL,
	"created_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	"publish_at" bigint,
	"activate_at" bigint,
	"retire_at" bigint,
	"unpublish_at" bigint,
	"compromised_at" bigint,
	CONSTRAINT "realm_keys_realm_id_kid_unique" UNIQUE("realm_id","kid"),
	CONSTRAINT "realm_keys_scope_id_not_empty" CHECK ("realm_keys"."scope_id" <> ''),
	CONSTRAINT "realm_keys_compromised_at_matches_status" CHECK (("realm_keys"."status" = 'compromised') = ("realm_keys"."compromised_at" is not null)),
	CONSTRAINT "realm_keys_unpublish_not_before_publish" CHECK ("realm_keys"."unpublish_at" is null or "realm_keys"."publish_at" is null or "realm_keys"."unpublish_at" >= "realm_keys"."publish_at")
);
--> statement-breakpoint
CREATE TABLE "realm_public_keys" (
	"kid" varchar(255) NOT NULL,
	"realm_id" uuid NOT NULL,
	"purpose" varchar(64) NOT NULL,
	"algorithm" varchar(32) NOT NULL,
	"status" realm_key_status NOT NULL,
	"public_jwk" jsonb NOT NULL,
	"publish_at" bigint NOT NULL,
	"unpublish_at" bigint,
	CONSTRAINT "realm_public_keys_pk" PRIMARY KEY("realm_id","kid"),
	CONSTRAINT "realm_public_keys_public_jwk_object" CHECK (jsonb_typeof("realm_public_keys"."public_jwk") = 'object'),
	CONSTRAINT "realm_public_keys_public_jwk_no_private_members" CHECK (not ("realm_public_keys"."public_jwk" ?| array['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k', 'priv'])),
	CONSTRAINT "realm_public_keys_unpublish_not_before_publish" CHECK ("realm_public_keys"."unpublish_at" is null or "realm_public_keys"."unpublish_at" >= "realm_public_keys"."publish_at")
);
--> statement-breakpoint
ALTER TABLE "realm_keys" ADD CONSTRAINT "realm_keys_realm_id_realms_id_fk" FOREIGN KEY ("realm_id") REFERENCES "public"."realms"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "realm_public_keys" ADD CONSTRAINT "realm_public_keys_realm_key_fk" FOREIGN KEY ("realm_id","kid") REFERENCES "public"."realm_keys"("realm_id","kid") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "idx_realm_keys_one_active" ON "realm_keys" USING btree ("realm_id","purpose",coalesce("scope_id", ''),"algorithm") WHERE "realm_keys"."status" = 'active';