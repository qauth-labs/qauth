CREATE TYPE "public"."admin_actor_kind" AS ENUM('human_admin', 'service_account', 'break_glass_operator', 'host_operator');--> statement-breakpoint
CREATE TYPE "public"."admin_audit_outcome" AS ENUM('succeeded', 'failed', 'denied');--> statement-breakpoint
CREATE TYPE "public"."admin_operation_class" AS ENUM('read', 'write', 'security');--> statement-breakpoint
CREATE TABLE "admin_audit_log" (
	"realm_id" uuid NOT NULL,
	"seq" bigint NOT NULL,
	"prev_hash" "bytea" NOT NULL,
	"row_hash" "bytea" NOT NULL,
	"actor_kind" "admin_actor_kind" NOT NULL,
	"actor_id" varchar(255) NOT NULL,
	"actor_realm_id" uuid,
	"act_chain" jsonb,
	"operation_id" varchar(128) NOT NULL,
	"operation_class" "admin_operation_class" NOT NULL,
	"effects" jsonb NOT NULL,
	"outcome" "admin_audit_outcome" NOT NULL,
	"masked_diff" jsonb,
	"approvals" jsonb NOT NULL,
	"request_digest" "bytea",
	"trace_id" varchar(128),
	"created_at" bigint NOT NULL,
	CONSTRAINT "admin_audit_log_pk" PRIMARY KEY("realm_id","seq"),
	CONSTRAINT "admin_audit_log_seq_positive" CHECK ("admin_audit_log"."seq" >= 1),
	CONSTRAINT "admin_audit_log_prev_hash_sha256" CHECK (octet_length("admin_audit_log"."prev_hash") = 32),
	CONSTRAINT "admin_audit_log_row_hash_sha256" CHECK (octet_length("admin_audit_log"."row_hash") = 32),
	CONSTRAINT "admin_audit_log_first_row_genesis" CHECK ("admin_audit_log"."seq" <> 1 or "admin_audit_log"."prev_hash" = decode(repeat('00', 32), 'hex')),
	CONSTRAINT "admin_audit_log_request_digest_sha256" CHECK ("admin_audit_log"."request_digest" is null or octet_length("admin_audit_log"."request_digest") = 32),
	CONSTRAINT "admin_audit_log_actor_id_not_empty" CHECK ("admin_audit_log"."actor_id" <> ''),
	CONSTRAINT "admin_audit_log_actor_realm_matches_kind" CHECK (("admin_audit_log"."actor_kind" in ('human_admin', 'service_account')) = ("admin_audit_log"."actor_realm_id" is not null)),
	CONSTRAINT "admin_audit_log_operation_id_not_empty" CHECK ("admin_audit_log"."operation_id" <> ''),
	CONSTRAINT "admin_audit_log_act_chain_shape" CHECK ("admin_audit_log"."act_chain" is null or (jsonb_typeof("admin_audit_log"."act_chain") = 'object' and "admin_audit_log"."act_chain" ? 'sub' and jsonb_typeof("admin_audit_log"."act_chain" -> 'act') = 'object')),
	CONSTRAINT "admin_audit_log_effects_is_array" CHECK (jsonb_typeof("admin_audit_log"."effects") = 'array'),
	CONSTRAINT "admin_audit_log_masked_diff_shape" CHECK ("admin_audit_log"."masked_diff" is null or (jsonb_typeof("admin_audit_log"."masked_diff") = 'object' and "admin_audit_log"."masked_diff" ? 'before' and "admin_audit_log"."masked_diff" ? 'after')),
	CONSTRAINT "admin_audit_log_approvals_is_array" CHECK (jsonb_typeof("admin_audit_log"."approvals") = 'array')
);
--> statement-breakpoint
CREATE TABLE "admin_audit_log_checkpoints" (
	"realm_id" uuid NOT NULL,
	"seq" bigint NOT NULL,
	"row_hash" "bytea" NOT NULL,
	"created_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	CONSTRAINT "admin_audit_log_checkpoints_pk" PRIMARY KEY("realm_id","seq"),
	CONSTRAINT "admin_audit_log_checkpoints_seq_positive" CHECK ("admin_audit_log_checkpoints"."seq" >= 1),
	CONSTRAINT "admin_audit_log_checkpoints_row_hash_sha256" CHECK (octet_length("admin_audit_log_checkpoints"."row_hash") = 32)
);
--> statement-breakpoint
-- Hand-written below this line: drizzle-kit does not model functions,
-- triggers or grants, so `db:generate` neither writes nor drops them.
--
-- The admin audit log is append-only (ADR-019 Decision 7, #448). These
-- triggers hold whoever writes, the table owner included, before any per-role
-- grants exist; the grants (`adminAuditLogWriterGrantStatements`) are the
-- second wall once the roles are split (#498). The one DELETE allowed is the
-- one `admin_audit_log_prune` performs: it marks its transaction with the
-- realm it prunes and has already written the checkpoint that covers every
-- row it deletes. Checkpoints are never changed or deleted.
CREATE FUNCTION "admin_audit_log_append_only"() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_TABLE_NAME = 'admin_audit_log' AND TG_OP = 'DELETE' THEN
    IF current_setting('qauth.admin_audit_log_prune', true) = OLD."realm_id"::text
       AND EXISTS (
         SELECT 1 FROM public."admin_audit_log_checkpoints" c
         WHERE c."realm_id" = OLD."realm_id" AND c."seq" >= OLD."seq"
       )
    THEN
      RETURN OLD;
    END IF;
  END IF;
  RAISE EXCEPTION '% is append-only: % refused', TG_TABLE_NAME, TG_OP
    USING ERRCODE = 'check_violation',
          CONSTRAINT = TG_TABLE_NAME || '_append_only',
          HINT = 'Rows are only inserted. The retention job removes the oldest rows of a realm through admin_audit_log_prune(realm_id, through_seq).';
END;
$$;--> statement-breakpoint
CREATE TRIGGER "admin_audit_log_append_only"
  BEFORE UPDATE OR DELETE ON "admin_audit_log"
  FOR EACH ROW
  EXECUTE FUNCTION "admin_audit_log_append_only"();--> statement-breakpoint
CREATE TRIGGER "admin_audit_log_no_truncate"
  BEFORE TRUNCATE ON "admin_audit_log"
  FOR EACH STATEMENT
  EXECUTE FUNCTION "admin_audit_log_append_only"();--> statement-breakpoint
CREATE TRIGGER "admin_audit_log_checkpoints_append_only"
  BEFORE UPDATE OR DELETE ON "admin_audit_log_checkpoints"
  FOR EACH ROW
  EXECUTE FUNCTION "admin_audit_log_append_only"();--> statement-breakpoint
CREATE TRIGGER "admin_audit_log_checkpoints_no_truncate"
  BEFORE TRUNCATE ON "admin_audit_log_checkpoints"
  FOR EACH STATEMENT
  EXECUTE FUNCTION "admin_audit_log_append_only"();--> statement-breakpoint
-- The retention job's only way to remove rows (ADR-020 §3). It deletes the
-- realm's rows up to and including `p_through_seq`, oldest first by
-- construction, and refuses when any of them is younger than 90 days, the
-- floor below which no realm setting may go. Before it deletes, it records the
-- `seq` and `row_hash` of the last row it removes as a checkpoint, so the
-- oldest retained row still verifies. It takes the realm's chain lock, the
-- same one `appendAdminAudit` takes, so no append interleaves.
--
-- SECURITY DEFINER, so a retention role can be granted EXECUTE without any
-- DELETE grant on the table; EXECUTE is revoked from PUBLIC below.
CREATE FUNCTION "admin_audit_log_prune"(p_realm_id uuid, p_through_seq bigint) RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_row_hash bytea;
  v_newest_created_at bigint;
  v_deleted bigint;
BEGIN
  IF p_realm_id IS NULL OR p_through_seq IS NULL THEN
    RAISE EXCEPTION 'admin_audit_log_prune needs a realm and a seq'
      USING ERRCODE = 'null_value_not_allowed';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended('qauth:admin-audit:' || p_realm_id::text, 0));

  SELECT "row_hash" INTO v_row_hash
    FROM public."admin_audit_log"
    WHERE "realm_id" = p_realm_id AND "seq" = p_through_seq;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'admin_audit_log has no row % in realm %', p_through_seq, p_realm_id
      USING ERRCODE = 'no_data_found',
            HINT = 'Prune through a seq that is still in the log.';
  END IF;

  SELECT max("created_at") INTO v_newest_created_at
    FROM public."admin_audit_log"
    WHERE "realm_id" = p_realm_id AND "seq" <= p_through_seq;
  IF v_newest_created_at > (extract(epoch FROM now()) * 1000)::bigint - 90::bigint * 86400000 THEN
    RAISE EXCEPTION 'admin_audit_log keeps every row for at least 90 days'
      USING ERRCODE = 'check_violation',
            CONSTRAINT = 'admin_audit_log_retention_floor',
            DETAIL = format('realm %s, a row up to seq %s is younger than 90 days', p_realm_id, p_through_seq);
  END IF;

  INSERT INTO public."admin_audit_log_checkpoints" ("realm_id", "seq", "row_hash")
    VALUES (p_realm_id, p_through_seq, v_row_hash);

  PERFORM set_config('qauth.admin_audit_log_prune', p_realm_id::text, true);
  DELETE FROM public."admin_audit_log"
    WHERE "realm_id" = p_realm_id AND "seq" <= p_through_seq;
  GET DIAGNOSTICS v_deleted = ROW_COUNT;
  PERFORM set_config('qauth.admin_audit_log_prune', '', true);

  RETURN v_deleted;
END;
$$;--> statement-breakpoint
REVOKE ALL ON FUNCTION "admin_audit_log_prune"(uuid, bigint) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON TABLE "admin_audit_log", "admin_audit_log_checkpoints" FROM PUBLIC;
