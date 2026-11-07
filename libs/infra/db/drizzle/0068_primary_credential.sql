-- The primary identity of each account (ADR-015 Decision 8 and question 13, #846).
--
-- An account is a verified owner of an agent only when its primary identity is
-- proved. The primary identity is the credential that created the account; this
-- migration marks it, `user_credentials.is_primary`, and holds the rule:
--
-- 1. At most one primary credential per user (the partial unique index).
-- 2. The backfill marks, for every user, the credential that created the
--    account: the user's oldest credential (by `created_at`, then `id`), never
--    an authenticator app (`totp`), which is a second factor bound to an
--    account that already exists. A user whose only credential is an
--    authenticator app, or who has none, gets no primary credential. An
--    account cannot delete its password, nor its last way to sign in, so the
--    oldest credential left is the one that created the account, except where
--    the owner removed that one (a passkey, or an upstream identity, unlinked)
--    after adding the next: then the next, which the owner added, is marked.
-- 3. From now on a credential is the primary identity only when it is written
--    with the account: it is the user's first credential, it is no
--    authenticator app, and it carries the account's own `created_at`, which
--    both rows take from the transaction that writes them (`NOW()`). Every
--    account-creation path writes the user and the credential that creates it
--    in one transaction. The database marks such a credential whatever the
--    writer passed, so a release before this one, which never names the
--    column, keeps creating accounts with their primary credential during a
--    rolling upgrade. Any other credential that claims the mark is refused;
--    one written later to an account that has none is not marked.
-- 4. The mark never moves in 1.0: an update that sets or clears it, or moves a
--    primary credential to another user, is refused. Deleting the primary
--    credential leaves the account with none, and then it is not a verified
--    owner: no later credential makes an account verified.
ALTER TABLE "user_credentials" ADD COLUMN "is_primary" boolean DEFAULT false NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "idx_user_credentials_primary_unique" ON "user_credentials" USING btree ("user_id") WHERE "user_credentials"."is_primary";
--> statement-breakpoint
UPDATE "user_credentials" AS c
SET "is_primary" = true
FROM (
  SELECT DISTINCT ON ("user_id") "id"
  FROM "user_credentials"
  WHERE "provider_type" <> 'totp'
  ORDER BY "user_id", "created_at", "id"
) AS creating
WHERE c."id" = creating."id";
--> statement-breakpoint
CREATE FUNCTION "user_credentials_primary_identity"() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION 'a primary identity is marked when the account is created, and never moves'
      USING ERRCODE = 'check_violation',
            CONSTRAINT = 'user_credentials_primary_permanent',
            TABLE = 'user_credentials',
            DETAIL = format('credential %s', OLD."id");
  END IF;

  IF NEW."provider_type" = 'totp' THEN
    IF NEW."is_primary" THEN
      RAISE EXCEPTION 'an authenticator app is never an account''s primary identity'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'user_credentials_primary_first',
              TABLE = 'user_credentials',
              DETAIL = format('user %s', NEW."user_id");
    END IF;
  ELSIF NOT EXISTS (
    SELECT 1 FROM public."user_credentials" c WHERE c."user_id" = NEW."user_id"
  ) AND EXISTS (
    SELECT 1 FROM public."users" u
    WHERE u."id" = NEW."user_id" AND u."created_at" = NEW."created_at"
  ) THEN
    NEW."is_primary" := true;
  ELSIF NEW."is_primary" THEN
    RAISE EXCEPTION 'only the credential that creates an account is its primary identity'
      USING ERRCODE = 'check_violation',
            CONSTRAINT = 'user_credentials_primary_first',
            TABLE = 'user_credentials',
            DETAIL = format('user %s', NEW."user_id");
  END IF;
  RETURN NEW;
END;
$$;
--> statement-breakpoint
CREATE TRIGGER "user_credentials_primary_insert"
  BEFORE INSERT ON "user_credentials"
  FOR EACH ROW
  EXECUTE FUNCTION "user_credentials_primary_identity"();
--> statement-breakpoint
CREATE TRIGGER "user_credentials_primary_update"
  BEFORE UPDATE ON "user_credentials"
  FOR EACH ROW
  WHEN (
    NEW."is_primary" IS DISTINCT FROM OLD."is_primary"
    OR (OLD."is_primary" AND NEW."user_id" IS DISTINCT FROM OLD."user_id")
  )
  EXECUTE FUNCTION "user_credentials_primary_identity"();
