-- #1073: store, beside each realm's state of an AuthMethod plugin, whose
-- client the signer role signs the plugin's client assertions for: the client
-- id QAuth is registered under at the provider, the `iss` of a signed client
-- secret when that is not the client id (Sign in with Apple's Team ID), and
-- the algorithm of the key registered there. A preset makes them from its
-- config with its own code, which the signer's process never loads, so the
-- admin API derives them at each configure and enable, and the signer reads
-- them here.
--
-- Three nullable columns with no default, so Postgres adds them without
-- rewriting the table, and every existing row gets NULL in all three: the
-- signer signs nothing for such a row until a configure or an enable writes it
-- again, as it signed nothing before this migration. A release before this one
-- never names the columns: its insert leaves them NULL and its update keeps
-- them, so during a rolling upgrade a configure on an old node can leave a
-- record the new node wrote; a configure after the upgrade writes it again.
-- Forward-only: nothing is rewritten.
--
-- The CHECKs hold the stored forms: a client id and its algorithm together,
-- an issuer only beside them, no empty value, and an algorithm the signer
-- signs client assertions with. Every existing row passes them (NULL in all).
ALTER TABLE "realm_auth_method_plugins" ADD COLUMN "assertion_client_id" varchar(255);--> statement-breakpoint
ALTER TABLE "realm_auth_method_plugins" ADD COLUMN "assertion_issuer" varchar(255);--> statement-breakpoint
ALTER TABLE "realm_auth_method_plugins" ADD COLUMN "assertion_algorithm" varchar(16);--> statement-breakpoint
ALTER TABLE "realm_auth_method_plugins" ADD CONSTRAINT "realm_auth_method_plugins_assertion_client_pair" CHECK (("realm_auth_method_plugins"."assertion_client_id" IS NULL) = ("realm_auth_method_plugins"."assertion_algorithm" IS NULL));--> statement-breakpoint
ALTER TABLE "realm_auth_method_plugins" ADD CONSTRAINT "realm_auth_method_plugins_assertion_issuer_client" CHECK ("realm_auth_method_plugins"."assertion_issuer" IS NULL OR "realm_auth_method_plugins"."assertion_client_id" IS NOT NULL);--> statement-breakpoint
ALTER TABLE "realm_auth_method_plugins" ADD CONSTRAINT "realm_auth_method_plugins_assertion_client_id_form" CHECK ("realm_auth_method_plugins"."assertion_client_id" <> '');--> statement-breakpoint
ALTER TABLE "realm_auth_method_plugins" ADD CONSTRAINT "realm_auth_method_plugins_assertion_issuer_form" CHECK ("realm_auth_method_plugins"."assertion_issuer" <> '');--> statement-breakpoint
ALTER TABLE "realm_auth_method_plugins" ADD CONSTRAINT "realm_auth_method_plugins_assertion_algorithm_form" CHECK ("realm_auth_method_plugins"."assertion_algorithm" IN ('RS256', 'ES256', 'EdDSA'));