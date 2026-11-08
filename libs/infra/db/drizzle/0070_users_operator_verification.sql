-- #1052: an operator may verify an account (ADR-015 Decision 8, amended
-- 2026-11-08). The admin security operation `users.verify` records it, and so
-- does the migration runner's `verify-account` command on the server host. It
-- is the operator's attestation of the account: the sign-in gate and the
-- verified-owner check count it beside the proof of the primary identity, and
-- it claims an unclaimed account (ADR-017). It never touches `email_verified`.
--
-- Two nullable columns with no default, so Postgres adds them without
-- rewriting the table, and every existing account reads as one no operator
-- verified. A release before this one never names them: its inserts leave
-- both NULL and its updates keep them, and it does not count them either, so
-- during a rolling upgrade an account verified this way passes the gate only
-- on nodes of this release. Forward-only: nothing is rewritten.
--
-- The CHECKs hold the recorded form: both columns set or neither, and the
-- operator as `operator:<admin account id>`, `operator_cli:<os user>` or
-- `operator_cli` (`OPERATOR_VERIFIED_BY_PATTERN` of shared-validation). Every
-- existing row passes them (NULL in both).
ALTER TABLE "users" ADD COLUMN "operator_verified_at" bigint;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "operator_verified_by" varchar(320);--> statement-breakpoint
ALTER TABLE "users" ADD CONSTRAINT "users_operator_verification_pair" CHECK (("users"."operator_verified_at" IS NULL) = ("users"."operator_verified_by" IS NULL));--> statement-breakpoint
ALTER TABLE "users" ADD CONSTRAINT "users_operator_verified_by_form" CHECK ("users"."operator_verified_by" ~ '^(operator:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|operator_cli(:[^[:cntrl:]]{1,255})?)$');--> statement-breakpoint
-- users.verify runs as the admin role's database user (ADR-019 Decision 7),
-- which reads users and nothing of user_credentials, and writes neither. Two
-- functions give it what the operation needs and no more.
--
-- user_credential_proofs: the account's credentials in its realm, as its
-- approver is shown them. It returns nothing secret: of credential_data only
-- `email_verified`, `user_verified` and `kind`, the fields that say what a
-- credential proves; no password hash, TOTP secret, passkey key or upstream
-- claim. The identifier only of a password credential, its address. STABLE.
--
-- users_record_operator_verification: the verification of an enabled account
-- no operator verified yet, recorded as `operator:<admin account id>`, with
-- its updated_at, at the caller's clock. It returns the two columns it wrote,
-- or no row when it wrote nothing. It touches no other column, so the admin
-- role holds no UPDATE on users: it cannot enable an account or change a
-- profile. The CHECKs above still hold what it writes.
--
-- Both are SECURITY DEFINER: they read and write the tables as their owner.
-- Their search_path is pinned and EXECUTE is revoked from PUBLIC; the
-- per-role grants give them to the admin role alone.
CREATE FUNCTION "user_credential_proofs"(p_realm_id uuid, p_user_id uuid)
RETURNS TABLE ("id" uuid, "provider_type" text, "is_primary" boolean, "disabled_at" bigint, "identifier" text, "proof_data" jsonb)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT c."id",
         c."provider_type",
         c."is_primary",
         c."disabled_at",
         CASE WHEN c."provider_type" = 'password' THEN c."external_sub" END,
         jsonb_strip_nulls(jsonb_build_object(
           'email_verified', c."credential_data" -> 'email_verified',
           'user_verified', c."credential_data" -> 'user_verified',
           'kind', c."credential_data" -> 'kind'
         ))
    FROM public."user_credentials" c
   WHERE c."realm_id" = p_realm_id
     AND c."user_id" = p_user_id
$$;--> statement-breakpoint
REVOKE ALL ON FUNCTION "user_credential_proofs"(uuid, uuid) FROM PUBLIC;--> statement-breakpoint
CREATE FUNCTION "users_record_operator_verification"(p_realm_id uuid, p_user_id uuid, p_operator_id uuid, p_at bigint)
RETURNS TABLE ("operator_verified_at" bigint, "operator_verified_by" varchar)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  UPDATE public."users" u
     SET "operator_verified_at" = p_at,
         "operator_verified_by" = 'operator:' || p_operator_id::text,
         "updated_at" = p_at
   WHERE u."realm_id" = p_realm_id
     AND u."id" = p_user_id
     AND u."enabled"
     AND u."operator_verified_at" IS NULL
  RETURNING u."operator_verified_at", u."operator_verified_by"
$$;--> statement-breakpoint
REVOKE ALL ON FUNCTION "users_record_operator_verification"(uuid, uuid, uuid, bigint) FROM PUBLIC;
