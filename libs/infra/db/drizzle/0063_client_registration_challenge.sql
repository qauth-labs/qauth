-- #643 (ADR-017 Decision 7, F1b): whether a registration this client starts
-- must pass the bot challenge first, whatever the realm's policy. Operator-set:
-- the `db:seed-oauth-clients` manifest writes it, and no registration path can.
-- A new nullable column with no default, so every existing row reads NULL,
-- which leaves the requirement to the realm, and the previous release, which
-- never names it, keeps working during a rolling upgrade. Forward-only:
-- nothing is rewritten.
ALTER TABLE "oauth_clients" ADD COLUMN "registration_challenge" boolean;
