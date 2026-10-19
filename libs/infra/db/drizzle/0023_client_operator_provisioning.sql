-- ANT-2026-O8U3P920: a positive, operator-set trust marker. Only a client with
-- provisioned_by_operator = true receives authorization error responses by an
-- automatic redirect (RFC 9700 §4.11.2); every other client gets them on an
-- issuer page. New rows default to false.
ALTER TABLE "oauth_clients" ADD COLUMN "provisioned_by_operator" boolean DEFAULT false NOT NULL;
--> statement-breakpoint
-- Backfill: true only for a row that no self-service path can have written,
-- judged from the columns those paths always set.
--   - developer_id IS NULL: POST /api/clients (and a developer-attributed
--     POST /oauth/register) records the owner.
--   - dynamic_registered_at IS NULL: POST /oauth/register stamps it.
--   - no metadata.registrationType: POST /oauth/register writes 'dynamic',
--     CIMD materialisation writes 'cimd'; the operator paths (the system
--     client, db:seed-oauth-clients, db:seed) write no metadata at all.
--   - no client-management audit row: catches a POST /api/clients client
--     whose owner's user row was deleted (developer_id is SET NULL then).
-- What is left is the system client and the clients the seed scripts
-- created. Anything the columns cannot vouch for stays false, the safe
-- answer: such a client gets the issuer page instead of a 302, and an
-- operator who wants the redirect for it re-provisions it through the
-- db:seed-oauth-clients manifest (--rotate) or sets the column by hand.
UPDATE "oauth_clients" c
SET "provisioned_by_operator" = true
WHERE c."developer_id" IS NULL
  AND c."dynamic_registered_at" IS NULL
  AND c."metadata"->>'registrationType' IS NULL
  AND NOT EXISTS (
    SELECT 1 FROM "audit_logs" a
    WHERE a."oauth_client_id" = c."id"
      AND a."event" IN (
        'oauth.client.created',
        'oauth.client.registered',
        'oauth.client.updated',
        'oauth.client.secret_regenerated'
      )
  );
--> statement-breakpoint
-- ANT-2026-DR5XI3LV: an operator-only suspension, separate from `enabled`,
-- which is the owner's switch again (PATCH /api/clients/:id may set it either
-- way). A suspended client is refused wherever a disabled one is.
ALTER TABLE "oauth_clients" ADD COLUMN "suspended" boolean DEFAULT false NOT NULL;
--> statement-breakpoint
ALTER TABLE "oauth_clients" ADD COLUMN "suspended_at" bigint;
--> statement-breakpoint
-- Backfill: every client that is disabled when this runs is also suspended.
-- Until now `enabled = false` was the operator's only switch (an UPDATE by
-- hand), and the row does not record who cleared it. Since the owner may now
-- re-enable a client, carrying a disable over as `enabled = false` alone would
-- hand an operator's cut-off back to the owner. Suspending every disabled row
-- keeps today's behaviour exactly: nobody but an operator can bring such a
-- client back. A row the owner had disabled itself stays suspended until an
-- operator lifts it (db:suspend-oauth-client --lift), after which the owner
-- re-enables it as usual.
UPDATE "oauth_clients"
SET "suspended" = true,
    "suspended_at" = (EXTRACT(EPOCH FROM now()) * 1000)::bigint
WHERE "enabled" = false;
