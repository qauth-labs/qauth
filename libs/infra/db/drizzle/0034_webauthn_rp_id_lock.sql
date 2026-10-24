ALTER TABLE "realms" ADD COLUMN "webauthn_rp_id_locked_at" bigint;--> statement-breakpoint
-- Hand-written below this line: drizzle-kit does not model functions or
-- triggers, so `db:generate` neither writes nor drops them.
--
-- The passkey RP ID lock moves to a column of its own (ADR-019 Decision 2,
-- #553). Under migration 0028 (#467) a non-NULL `webauthn_rp_id` was the lock:
-- only the first enrolment wrote it, and nothing could change it after. From
-- here `webauthn_rp_id` is the operator's setting, NULL meaning the realm's
-- primary host, and `webauthn_rp_id_locked_at` is the lock.
--
-- A realm 0028 locked stays locked under the RP ID it stores. Its lock time is
-- its first passkey's, or its last update's if that passkey is gone. A realm
-- with a passkey and no stored RP ID cannot come from 0028, but would be locked
-- too, under its primary host: locking is the side that orphans nothing.
UPDATE "realms"
SET "webauthn_rp_id_locked_at" = coalesce(
  (
    SELECT min("user_credentials"."created_at")
    FROM "user_credentials"
    WHERE "user_credentials"."realm_id" = "realms"."id"
      AND "user_credentials"."provider_type" = 'webauthn'
  ),
  "realms"."updated_at"
)
WHERE "realms"."webauthn_rp_id" IS NOT NULL
  OR EXISTS (
    SELECT 1
    FROM "user_credentials"
    WHERE "user_credentials"."realm_id" = "realms"."id"
      AND "user_credentials"."provider_type" = 'webauthn'
  );--> statement-breakpoint
-- 0028's rule refused every change of a non-NULL RP ID, so an operator could
-- not move from a parent domain back to the realm host before any passkey
-- existed. It gives way to the lock below.
DROP TRIGGER "realms_webauthn_rp_id_permanent" ON "realms";--> statement-breakpoint
DROP FUNCTION "realms_webauthn_rp_id_permanent"();--> statement-breakpoint
-- Once a realm's first passkey is enrolled, its RP ID and the lock itself are
-- permanent, whoever writes them: another RP ID would orphan every enrolled
-- passkey, and clearing the lock would allow one. The lock is a database rule,
-- not only a service rule, for that reason.
CREATE FUNCTION "realms_webauthn_rp_id_locked"() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'realms.webauthn_rp_id is locked by the realm''s first passkey enrolment'
    USING ERRCODE = 'check_violation',
          CONSTRAINT = 'realms_webauthn_rp_id_locked',
          DETAIL = format('realm %s, locked at %s', OLD."id", OLD."webauthn_rp_id_locked_at"),
          HINT = 'Neither the RP ID nor its lock can change once a passkey is enrolled. Another RP ID would orphan every enrolled passkey.';
END;
$$;--> statement-breakpoint
CREATE TRIGGER "realms_webauthn_rp_id_locked"
  BEFORE UPDATE ON "realms"
  FOR EACH ROW
  WHEN (
    OLD."webauthn_rp_id_locked_at" IS NOT NULL
    AND (
      NEW."webauthn_rp_id" IS DISTINCT FROM OLD."webauthn_rp_id"
      OR NEW."webauthn_rp_id_locked_at" IS DISTINCT FROM OLD."webauthn_rp_id_locked_at"
    )
  )
  EXECUTE FUNCTION "realms_webauthn_rp_id_locked"();
