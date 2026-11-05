-- #640 (ADR-017 Decision 8, question 13): the hosted flows a redirect-flow
-- client may start beyond sign-in, as a JSON list; as of #640 only `register`,
-- which lets the client start registration with `prompt=create` while the
-- realm's `registration_allowed` is on too. Operator-set: the
-- `db:seed-oauth-clients` manifest writes it, and no registration path can.
-- A new nullable column with no default, so every existing row reads NULL,
-- which allows no hosted flow, and the previous release, which never names
-- it, keeps working during a rolling upgrade. Forward-only: nothing is
-- rewritten. The CHECK keeps the stored form a list.
ALTER TABLE "oauth_clients" ADD COLUMN "hosted_flows" jsonb;--> statement-breakpoint
ALTER TABLE "oauth_clients" ADD CONSTRAINT "oauth_clients_hosted_flows_array" CHECK ("oauth_clients"."hosted_flows" IS NULL OR jsonb_typeof("oauth_clients"."hosted_flows") = 'array');