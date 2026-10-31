-- #631: the operator-set first-party client profile (ADR-017 Decision 2).
-- Three nullable columns with no default and the four CHECKs of the decision.
-- Forward-only: nothing is rewritten. Every existing client, and every client
-- the previous release still creates or updates during a rolling upgrade, has
-- no profile, no policy and no reason, which every CHECK accepts: the previous
-- release keeps working on the new schema.
--
-- The CHECKs: a profile only on a client the operator wrote (no developer, no
-- agent, no dynamic registration, no CIMD document); a profile only with
-- private_key_jwt; a policy exactly on native_backend (null-safe, so a policy
-- on a row with no profile is refused too); native_backend only with the
-- authorization_code grant.
--
-- No LOCK first, for the reason 0047 gives: run after it in one transaction,
-- this already holds "oauth_clients".
CREATE TYPE "public"."first_party_profile" AS ENUM('web_redirect', 'native_backend');--> statement-breakpoint
ALTER TABLE "oauth_clients" ADD COLUMN "first_party_profile" "first_party_profile";--> statement-breakpoint
ALTER TABLE "oauth_clients" ADD COLUMN "first_party_policy" jsonb;--> statement-breakpoint
ALTER TABLE "oauth_clients" ADD COLUMN "first_party_reason" text;--> statement-breakpoint
ALTER TABLE "oauth_clients" ADD CONSTRAINT "oauth_clients_first_party_operator_only" CHECK ("oauth_clients"."first_party_profile" IS NULL OR ("oauth_clients"."dynamic_registered_at" IS NULL AND "oauth_clients"."developer_id" IS NULL AND "oauth_clients"."is_agent" = false AND coalesce("oauth_clients"."metadata"->>'registrationType', '') NOT IN ('dynamic', 'cimd')));--> statement-breakpoint
ALTER TABLE "oauth_clients" ADD CONSTRAINT "oauth_clients_first_party_private_key_jwt" CHECK ("oauth_clients"."first_party_profile" IS NULL OR "oauth_clients"."token_endpoint_auth_method" = 'private_key_jwt');--> statement-breakpoint
ALTER TABLE "oauth_clients" ADD CONSTRAINT "oauth_clients_first_party_policy_native" CHECK (("oauth_clients"."first_party_profile" IS NOT DISTINCT FROM 'native_backend') = ("oauth_clients"."first_party_policy" IS NOT NULL));--> statement-breakpoint
ALTER TABLE "oauth_clients" ADD CONSTRAINT "oauth_clients_first_party_native_authorization_code" CHECK ("oauth_clients"."first_party_profile" IS DISTINCT FROM 'native_backend' OR "oauth_clients"."grant_types" ? 'authorization_code');
