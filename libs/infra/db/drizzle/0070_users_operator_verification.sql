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
ALTER TABLE "users" ADD CONSTRAINT "users_operator_verified_by_form" CHECK ("users"."operator_verified_by" ~ '^(operator:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|operator_cli(:[^[:cntrl:]]{1,255})?)$');
