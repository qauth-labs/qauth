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
--> statement-breakpoint
-- A writer that predates the column inserts no value: the previous release,
-- which keeps serving on this schema during a rolling upgrade (operate/upgrades).
-- Its insert takes the start of the family the token joins, so a rotation it
-- serves never restarts the family's clock, or now when the token starts a
-- family. The current release always sets the column, so the trigger never
-- fires for it. NOT NULL is checked after BEFORE triggers.
--
-- The function pins its search_path and names the table with its schema, so
-- no caller can swap in its own operators or tables.
CREATE FUNCTION "refresh_tokens_family_created_at_fill"() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  NEW."family_created_at" := COALESCE(
    (SELECT min(t."family_created_at")
       FROM public."refresh_tokens" t
       WHERE t."family_id" = NEW."family_id"),
    EXTRACT(EPOCH FROM now())::bigint * 1000
  );
  RETURN NEW;
END;
$$;
--> statement-breakpoint
CREATE TRIGGER "refresh_tokens_family_created_at_fill"
  BEFORE INSERT ON "refresh_tokens"
  FOR EACH ROW
  WHEN (NEW."family_created_at" IS NULL)
  EXECUTE FUNCTION "refresh_tokens_family_created_at_fill"();
