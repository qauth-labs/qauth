-- #600: each realm's state of each installed AuthMethod plugin (ADR-019
-- Decisions 10 and 12): whether the realm has it on, the plain members of its
-- config, and the ciphertext of each secret member, encrypted with the realm's
-- data_at_rest key. A new table that no earlier release reads or writes, so
-- the previous release keeps working on the new schema during a rolling
-- upgrade. Forward-only: nothing is rewritten.
--
-- The CHECKs hold the stored forms: a plugin id under the contract's id rule,
-- a config and a secrets map that are JSON objects, every secret a
-- v1.<kid>.<iv>.<ciphertext> string (a value of any other form would be one in
-- the clear), and a version above zero. The ciphertext CHECK passes a secrets
-- value that is no object, which secrets_object refuses: its strict jsonpath
-- would raise an error on an array or a scalar, and it runs first.
CREATE TABLE "realm_auth_method_plugins" (
	"realm_id" uuid NOT NULL,
	"plugin_id" varchar(63) NOT NULL,
	"enabled" boolean DEFAULT false NOT NULL,
	"config" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"secrets" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"version" integer DEFAULT 1 NOT NULL,
	"created_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	"updated_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	CONSTRAINT "realm_auth_method_plugins_pkey" PRIMARY KEY("realm_id","plugin_id"),
	CONSTRAINT "realm_auth_method_plugins_plugin_id_form" CHECK ("realm_auth_method_plugins"."plugin_id" ~ '^[a-z][a-z0-9_-]{0,62}$'),
	CONSTRAINT "realm_auth_method_plugins_config_object" CHECK (jsonb_typeof("realm_auth_method_plugins"."config") = 'object'),
	CONSTRAINT "realm_auth_method_plugins_secrets_object" CHECK (jsonb_typeof("realm_auth_method_plugins"."secrets") = 'object'),
	CONSTRAINT "realm_auth_method_plugins_secrets_ciphertext" CHECK (jsonb_typeof("realm_auth_method_plugins"."secrets") <> 'object' OR NOT jsonb_path_exists("realm_auth_method_plugins"."secrets", 'strict $.* ? (@.type() != "string" || !(@ like_regex "^v1[.][^.]+[.][^.]+[.][^.]+$"))')),
	CONSTRAINT "realm_auth_method_plugins_version_positive" CHECK ("realm_auth_method_plugins"."version" > 0)
);
--> statement-breakpoint
ALTER TABLE "realm_auth_method_plugins" ADD CONSTRAINT "realm_auth_method_plugins_realm_id_realms_id_fk" FOREIGN KEY ("realm_id") REFERENCES "public"."realms"("id") ON DELETE cascade ON UPDATE no action;