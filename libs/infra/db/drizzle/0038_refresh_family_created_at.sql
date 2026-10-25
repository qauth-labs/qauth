-- #552 (ADR-019 Decision 3): record when each refresh-token family started, and
-- the end of the browser session that started it, so a realm's
-- sso_max_lifespan can cap the family and no family outlives its session.
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
-- The absolute end of the browser session that started the family, copied from
-- the authorization code at the exchange and on every rotation. NULL for a
-- family no browser session started (/auth/login, the legacy Bearer path), and
-- for every family that exists now: its start plus the limit caps it alone.
ALTER TABLE "authorization_codes" ADD COLUMN "session_expires_at" bigint;
--> statement-breakpoint
ALTER TABLE "refresh_tokens" ADD COLUMN "family_session_expires_at" bigint;
--> statement-breakpoint
-- A maximum session length of zero or less would end every session and every
-- family at its start. Such a value could only have been written by hand; it
-- becomes no limit, the column's meaning for NULL, before the CHECK refuses it.
UPDATE "realms" SET "sso_max_lifespan" = NULL WHERE "sso_max_lifespan" <= 0;
--> statement-breakpoint
ALTER TABLE "realms" ADD CONSTRAINT "realms_sso_max_lifespan_positive" CHECK ("realms"."sso_max_lifespan" IS NULL OR "realms"."sso_max_lifespan" > 0);
--> statement-breakpoint
-- An idle timeout of zero or less would end every session at its first request
-- after sign-in. It gets the same treatment: no limit, then the CHECK.
UPDATE "realms" SET "sso_idle_timeout" = NULL WHERE "sso_idle_timeout" <= 0;
--> statement-breakpoint
ALTER TABLE "realms" ADD CONSTRAINT "realms_sso_idle_timeout_positive" CHECK ("realms"."sso_idle_timeout" IS NULL OR "realms"."sso_idle_timeout" > 0);
--> statement-breakpoint
-- A writer that predates these columns inserts no value: the previous release,
-- which keeps serving on this schema during a rolling upgrade (operate/upgrades).
-- Its insert takes the start and the session end of the family the token joins,
-- so a rotation it serves never restarts the family's clock or drops its
-- session's cap; a token that starts a family gets now and no session end. The
-- current release always sets family_created_at, so the trigger never fires for
-- it. NOT NULL is checked after BEFORE triggers.
--
-- The function pins its search_path and names the table with its schema, so
-- no caller can swap in its own operators or tables.
CREATE FUNCTION "refresh_tokens_family_created_at_fill"() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  SELECT min(t."family_created_at"), min(t."family_session_expires_at")
    INTO NEW."family_created_at", NEW."family_session_expires_at"
    FROM public."refresh_tokens" t
    WHERE t."family_id" = NEW."family_id";
  NEW."family_created_at" := COALESCE(
    NEW."family_created_at",
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
