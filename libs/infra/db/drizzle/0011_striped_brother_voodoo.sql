-- #230 (ADR-002): drop the legacy identity columns — the point of no return.
-- The drizzle migrator runs each migration transactionally: if the guard
-- below raises, NOTHING in this file is applied.
--
-- There is NO down migration by design. password_hash and email are
-- unrecoverable after the drop; the only undo is restoring the pre-migration
-- database backup mandated by the CHANGELOG runbook.
DO $$
DECLARE
  missing_password_credentials bigint;
  missing_any_credentials bigint;
BEGIN
  SELECT count(*) INTO missing_password_credentials
  FROM users u
  WHERE u.password_hash IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM user_credentials uc
      WHERE uc.user_id = u.id AND uc.provider_type = 'password'
    );

  SELECT count(*) INTO missing_any_credentials
  FROM users u
  WHERE u.email IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM user_credentials uc WHERE uc.user_id = u.id
    );

  IF missing_password_credentials > 0 OR missing_any_credentials > 0 THEN
    RAISE EXCEPTION 'QAuth migration 0011 aborted: % user(s) with a password hash lack a password credential row and % user(s) with an email lack any credential row — their identity data exists ONLY in the legacy columns this migration drops. Remediation: deploy the previous release (the last one containing the db:backfill-identity target), run the #226/#229 backfill runbook there (--refresh, then --verify-only; both must exit 0), then upgrade and retry. No data was modified.', missing_password_credentials, missing_any_credentials;
  END IF;
END $$;
--> statement-breakpoint
-- Rescue in-flight verification tokens minted without credential_id by a
-- straggling pre-#228 writer: idempotent re-run of the 0010 backfill UPDATE.
UPDATE "email_verification_tokens" t
SET "credential_id" = uc."id"
FROM "user_credentials" uc
WHERE uc."user_id" = t."user_id"
  AND uc."provider_type" = 'password'
  AND t."credential_id" IS NULL;
--> statement-breakpoint
-- Delete the truly orphaned remainder before SET NOT NULL. Verification
-- tokens are hours-lived, re-requestable transients: the only remediation a
-- guard could demand is this same DELETE run by hand, and the affected user
-- just clicks resend once.
DO $$
DECLARE orphaned bigint;
BEGIN
  DELETE FROM email_verification_tokens WHERE credential_id IS NULL;
  GET DIAGNOSTICS orphaned = ROW_COUNT;
  IF orphaned > 0 THEN
    RAISE NOTICE 'QAuth migration 0011: deleted % verification token(s) with no resolvable credential; affected users can re-request verification.', orphaned;
  END IF;
END $$;
--> statement-breakpoint
ALTER TABLE "email_verification_tokens" DROP CONSTRAINT "email_verification_tokens_user_id_users_id_fk";
--> statement-breakpoint
DROP INDEX "idx_users_realm_email_normalized_unique";--> statement-breakpoint
DROP INDEX "idx_users_email";--> statement-breakpoint
DROP INDEX "idx_users_realm_email_enabled";--> statement-breakpoint
DROP INDEX "idx_email_verification_tokens_user_id";--> statement-breakpoint
ALTER TABLE "email_verification_tokens" ALTER COLUMN "credential_id" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "users" DROP COLUMN "email";--> statement-breakpoint
ALTER TABLE "users" DROP COLUMN "email_normalized";--> statement-breakpoint
ALTER TABLE "users" DROP COLUMN "password_hash";--> statement-breakpoint
ALTER TABLE "email_verification_tokens" DROP COLUMN "user_id";