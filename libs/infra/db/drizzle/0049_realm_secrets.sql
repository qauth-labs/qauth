CREATE TABLE "realm_secrets" (
	"realm_id" uuid NOT NULL,
	"name" varchar(128) NOT NULL,
	"ciphertext" text,
	"key_id" varchar(255),
	"updated_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	CONSTRAINT "realm_secrets_pk" PRIMARY KEY("realm_id","name"),
	CONSTRAINT "realm_secrets_name_form" CHECK ("realm_secrets"."name" ~ '^[a-z][a-zA-Z0-9]*(\.[a-z][a-zA-Z0-9]*)+$'),
	CONSTRAINT "realm_secrets_value_and_key_together" CHECK (("realm_secrets"."ciphertext" IS NULL) = ("realm_secrets"."key_id" IS NULL)),
	CONSTRAINT "realm_secrets_ciphertext_form" CHECK ("realm_secrets"."ciphertext" IS NULL OR ("realm_secrets"."ciphertext" ~ '^v1\.[A-Za-z0-9_-]{1,255}\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22,}$' AND split_part("realm_secrets"."ciphertext", '.', 2) = "realm_secrets"."key_id"))
);
--> statement-breakpoint
ALTER TABLE "realm_secrets" ADD CONSTRAINT "realm_secrets_realm_id_realms_id_fk" FOREIGN KEY ("realm_id") REFERENCES "public"."realms"("id") ON DELETE cascade ON UPDATE no action;