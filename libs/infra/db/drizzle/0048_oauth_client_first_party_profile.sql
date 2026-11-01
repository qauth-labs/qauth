-- #631: the operator-set first-party client profile (ADR-017 Decision 2).
-- Three nullable columns with no default, the four CHECKs of the decision and
-- two on the stored forms. Forward-only: nothing is rewritten. Every existing
-- client, and every client the previous release still creates or updates
-- during a rolling upgrade, has no profile, no policy and no reason, which
-- every CHECK accepts: the previous release keeps working on the new schema.
--
-- The decision's CHECKs: a profile only on a client the operator wrote (no
-- developer, no agent, no dynamic registration, no CIMD document); a profile
-- only with private_key_jwt; a policy exactly on native_backend (null-safe, so
-- a policy on a row with no profile is refused too); native_backend only with
-- the authorization_code grant. The stored forms: a written reason exactly
-- with a profile, holding a character that is not white space and at most
-- 1000 characters long (what the client.first_party_changed event carries); a
-- policy that is a JSON object.
--
-- One ALTER TABLE for the three columns and the six CHECKs: Postgres takes
-- its ACCESS EXCLUSIVE lock on "oauth_clients" once and checks every new
-- CHECK in a single scan of the table, which dynamic registration can make
-- large, instead of one scan per CHECK. No LOCK first: that statement is the
-- only one here that locks a table, and it locks "oauth_clients" alone.
CREATE TYPE "public"."first_party_profile" AS ENUM('web_redirect', 'native_backend');--> statement-breakpoint
ALTER TABLE "oauth_clients"
  ADD COLUMN "first_party_profile" "first_party_profile",
  ADD COLUMN "first_party_policy" jsonb,
  ADD COLUMN "first_party_reason" text,
  ADD CONSTRAINT "oauth_clients_first_party_operator_only" CHECK ("oauth_clients"."first_party_profile" IS NULL OR ("oauth_clients"."dynamic_registered_at" IS NULL AND "oauth_clients"."developer_id" IS NULL AND "oauth_clients"."is_agent" = false AND coalesce("oauth_clients"."metadata"->>'registrationType', '') NOT IN ('dynamic', 'cimd'))),
  ADD CONSTRAINT "oauth_clients_first_party_private_key_jwt" CHECK ("oauth_clients"."first_party_profile" IS NULL OR "oauth_clients"."token_endpoint_auth_method" = 'private_key_jwt'),
  ADD CONSTRAINT "oauth_clients_first_party_policy_native" CHECK (("oauth_clients"."first_party_profile" IS NOT DISTINCT FROM 'native_backend') = ("oauth_clients"."first_party_policy" IS NOT NULL)),
  ADD CONSTRAINT "oauth_clients_first_party_native_authorization_code" CHECK ("oauth_clients"."first_party_profile" IS DISTINCT FROM 'native_backend' OR "oauth_clients"."grant_types" ? 'authorization_code'),
  ADD CONSTRAINT "oauth_clients_first_party_reason" CHECK (("oauth_clients"."first_party_profile" IS NULL) = ("oauth_clients"."first_party_reason" IS NULL) AND ("oauth_clients"."first_party_reason" IS NULL OR (char_length("oauth_clients"."first_party_reason") <= 1000 AND "oauth_clients"."first_party_reason" ~ '\S'))),
  ADD CONSTRAINT "oauth_clients_first_party_policy_object" CHECK ("oauth_clients"."first_party_policy" IS NULL OR jsonb_typeof("oauth_clients"."first_party_policy") = 'object');
