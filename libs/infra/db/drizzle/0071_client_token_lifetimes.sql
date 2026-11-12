-- #632: a client's own token lifetimes (ADR-020 §3), set through the admin
-- API's client operations. Each is at most the realm's: the admin API refuses
-- a longer one, and the token endpoint takes the shorter of the client's and
-- the realm's whatever is stored, so a realm that later shortens its own
-- still bounds every client.
--
-- Two nullable columns with no default, so Postgres adds them without
-- rewriting the table, and every existing client reads as one that takes the
-- realm's lifetimes. A release before this one never names them: during a
-- rolling upgrade its nodes keep issuing the realm's lifetimes to a client an
-- admin shortened, until every node runs this release. Forward-only: nothing
-- is rewritten.
--
-- The CHECKs hold the bounds of the realm's own lifetimes: a day for an
-- access token, 90 days for a refresh token. Every existing row passes them
-- (NULL in both).
ALTER TABLE "oauth_clients" ADD COLUMN "access_token_lifespan_seconds" integer;--> statement-breakpoint
ALTER TABLE "oauth_clients" ADD COLUMN "refresh_token_lifespan_seconds" integer;--> statement-breakpoint
ALTER TABLE "oauth_clients" ADD CONSTRAINT "oauth_clients_access_token_lifespan_bounds" CHECK ("oauth_clients"."access_token_lifespan_seconds" IS NULL OR "oauth_clients"."access_token_lifespan_seconds" BETWEEN 1 AND 86400);--> statement-breakpoint
ALTER TABLE "oauth_clients" ADD CONSTRAINT "oauth_clients_refresh_token_lifespan_bounds" CHECK ("oauth_clients"."refresh_token_lifespan_seconds" IS NULL OR "oauth_clients"."refresh_token_lifespan_seconds" BETWEEN 1 AND 7776000);
