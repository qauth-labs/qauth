-- #593: the domain an admin verified for a client (ADR-019 Decision 6), which
-- every screen that names the client shows first. Nullable with no default:
-- every existing client, and every client the previous release still creates
-- during a rolling upgrade, has none, which the screens show as an unverified
-- app. Nothing is rewritten. The CHECK holds the stored form (a lower-case DNS
-- name of two or more labels in ASCII), so a value written by hand never
-- reaches a screen in any other form.
ALTER TABLE "oauth_clients" ADD COLUMN "verified_domain" varchar(253);--> statement-breakpoint
ALTER TABLE "oauth_clients" ADD CONSTRAINT "oauth_clients_verified_domain_form" CHECK ("oauth_clients"."verified_domain" IS NULL OR "oauth_clients"."verified_domain" ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$');
