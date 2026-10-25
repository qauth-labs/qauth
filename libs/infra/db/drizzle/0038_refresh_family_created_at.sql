-- #552 (ADR-019 Decision 3): record when each refresh-token family started, so
-- a realm's sso_max_lifespan can cap the family.
--
-- The column is added without NOT NULL, filled, then made NOT NULL, so the
-- migration runs on a table that already has rows. A family started with its
-- earliest token, and the purge job deletes a family only whole, so that token
-- is still here while any token of the family is.
ALTER TABLE "refresh_tokens" ADD COLUMN "family_created_at" bigint;
--> statement-breakpoint
UPDATE "refresh_tokens" t
SET "family_created_at" = f."started"
FROM (
  SELECT "family_id", min("created_at") AS "started"
  FROM "refresh_tokens"
  GROUP BY "family_id"
) f
WHERE t."family_id" = f."family_id";
--> statement-breakpoint
ALTER TABLE "refresh_tokens" ALTER COLUMN "family_created_at" SET NOT NULL;
