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
-- The admin audit log is append-only (ADR-019 Decision 7, #448). The rules
-- below are database rules: they hold for every role whose statements fire
-- the triggers, so they stop an application bug, or a role granted more than
-- it should be, before the per-role grants exist (#498). A table owner or a
-- superuser can still disable or drop a trigger; against them only the role
-- split helps, and the hash chain shows what they changed as long as a later
-- row, a checkpoint or a copy of the head kept outside the database disagrees.
--
-- * A row is inserted only as the next link of its realm's chain: `seq` one
--   above the head (the newest row, else the newest checkpoint, else 0) and
--   `prev_hash` the head's hash.
-- * No row is updated, and neither table is truncated.
-- * A row is deleted only when a checkpoint covers its `seq`.
-- * A checkpoint is inserted only for a row still in the log, with that row's
--   hash, ahead of the realm's newest checkpoint, over an unbroken run of rows
--   since that checkpoint, and when none of those rows is younger than 90
--   days. So whoever may write checkpoints can do no more than a prune.
-- * No checkpoint is updated or deleted.
--
-- Every function pins its search_path and names tables with their schema, so
-- no caller can swap in its own operators or tables.
CREATE FUNCTION "admin_audit_log_follows_head"() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_seq bigint;
  v_hash bytea;
BEGIN
  SELECT l."seq", l."row_hash" INTO v_seq, v_hash
    FROM public."admin_audit_log" l
    WHERE l."realm_id" = NEW."realm_id"
    ORDER BY l."seq" DESC LIMIT 1;
  IF NOT FOUND THEN
    SELECT c."seq", c."row_hash" INTO v_seq, v_hash
      FROM public."admin_audit_log_checkpoints" c
      WHERE c."realm_id" = NEW."realm_id"
      ORDER BY c."seq" DESC LIMIT 1;
    IF NOT FOUND THEN
      v_seq := 0;
      v_hash := decode(repeat('00', 32), 'hex');
    END IF;
  END IF;
  IF NEW."seq" <> v_seq + 1 OR NEW."prev_hash" <> v_hash THEN
    RAISE EXCEPTION 'admin_audit_log row % of realm % does not follow the chain head %', NEW."seq", NEW."realm_id", v_seq
      USING ERRCODE = 'check_violation',
            CONSTRAINT = 'admin_audit_log_follows_head',
            HINT = 'Append through appendAdminAudit, which takes the realm''s chain lock.';
  END IF;
  RETURN NEW;
END;
$$;--> statement-breakpoint
CREATE TRIGGER "admin_audit_log_follows_head"
  BEFORE INSERT ON "admin_audit_log"
  FOR EACH ROW
  EXECUTE FUNCTION "admin_audit_log_follows_head"();--> statement-breakpoint
CREATE FUNCTION "admin_audit_log_append_only"() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF TG_TABLE_NAME = 'admin_audit_log' AND TG_OP = 'DELETE' THEN
    IF EXISTS (
      SELECT 1 FROM public."admin_audit_log_checkpoints" c
      WHERE c."realm_id" = OLD."realm_id" AND c."seq" >= OLD."seq"
    ) THEN
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
-- What makes a checkpoint, and so a prune, legitimate (ADR-020 §3: retention
-- removes only the oldest admin events and keeps them at least 90 days). The
-- run of rows it covers must be whole and linked by prev_hash, so a prune
-- cannot hide a row removed or a link changed earlier. Row hashes themselves
-- are not recomputed here: SQL has no RFC 8785 canonicalizer, so the retention
-- job runs verifyAdminAuditChain before it prunes.
CREATE FUNCTION "admin_audit_log_checkpoint_valid"() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_prev_seq bigint;
  v_prev_hash bytea;
  v_row_hash bytea;
  v_rows bigint;
  v_unlinked bigint;
  v_newest_created_at bigint;
BEGIN
  SELECT c."seq", c."row_hash" INTO v_prev_seq, v_prev_hash
    FROM public."admin_audit_log_checkpoints" c
    WHERE c."realm_id" = NEW."realm_id"
    ORDER BY c."seq" DESC LIMIT 1;
  IF NOT FOUND THEN
    v_prev_seq := 0;
    v_prev_hash := decode(repeat('00', 32), 'hex');
  END IF;
  IF NEW."seq" <= v_prev_seq THEN
    RAISE EXCEPTION 'a checkpoint of realm % must be past seq %', NEW."realm_id", v_prev_seq
      USING ERRCODE = 'check_violation', CONSTRAINT = 'admin_audit_log_checkpoints_forward';
  END IF;

  SELECT l."row_hash" INTO v_row_hash
    FROM public."admin_audit_log" l
    WHERE l."realm_id" = NEW."realm_id" AND l."seq" = NEW."seq";
  IF NOT FOUND OR v_row_hash <> NEW."row_hash" THEN
    RAISE EXCEPTION 'a checkpoint must name a row of the log and carry its hash'
      USING ERRCODE = 'check_violation', CONSTRAINT = 'admin_audit_log_checkpoints_match',
            DETAIL = format('realm %s, seq %s', NEW."realm_id", NEW."seq");
  END IF;

  SELECT count(*),
         count(*) FILTER (WHERE r."prev_hash" <> r."expected_prev"),
         max(r."created_at")
    INTO v_rows, v_unlinked, v_newest_created_at
    FROM (
      SELECT l."prev_hash", l."created_at",
             coalesce(lag(l."row_hash") OVER (ORDER BY l."seq"), v_prev_hash) AS "expected_prev"
        FROM public."admin_audit_log" l
        WHERE l."realm_id" = NEW."realm_id" AND l."seq" > v_prev_seq AND l."seq" <= NEW."seq"
    ) r;
  IF v_rows <> NEW."seq" - v_prev_seq OR v_unlinked > 0 THEN
    RAISE EXCEPTION 'the rows of realm % from seq % to % are not an unbroken chain', NEW."realm_id", v_prev_seq + 1, NEW."seq"
      USING ERRCODE = 'check_violation', CONSTRAINT = 'admin_audit_log_checkpoints_unbroken',
            HINT = 'Run verifyAdminAuditChain: a row was removed or relinked outside the log''s rules.';
  END IF;
  IF v_newest_created_at > (extract(epoch FROM now()) * 1000)::bigint - 90::bigint * 86400000 THEN
    RAISE EXCEPTION 'admin_audit_log keeps every row for at least 90 days'
      USING ERRCODE = 'check_violation', CONSTRAINT = 'admin_audit_log_retention_floor',
            DETAIL = format('realm %s, a row up to seq %s is younger than 90 days', NEW."realm_id", NEW."seq");
  END IF;
  RETURN NEW;
END;
$$;--> statement-breakpoint
CREATE TRIGGER "admin_audit_log_checkpoints_valid"
  BEFORE INSERT ON "admin_audit_log_checkpoints"
  FOR EACH ROW
  EXECUTE FUNCTION "admin_audit_log_checkpoint_valid"();--> statement-breakpoint
-- The retention job's way to remove rows. It deletes the realm's rows up to
-- and including `p_through_seq`, oldest first by construction, after writing
-- the checkpoint that covers them; the checkpoint trigger above refuses the
-- prune unless the rows are whole, linked and at least 90 days old. It takes
-- the realm's chain lock, the same one `appendAdminAudit` takes, so no append
-- interleaves.
--
-- SECURITY DEFINER, so a retention role can be granted EXECUTE without any
-- DELETE or checkpoint INSERT grant; EXECUTE is revoked from PUBLIC below.
CREATE FUNCTION "admin_audit_log_prune"(p_realm_id uuid, p_through_seq bigint) RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_row_hash bytea;
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

  INSERT INTO public."admin_audit_log_checkpoints" ("realm_id", "seq", "row_hash")
    VALUES (p_realm_id, p_through_seq, v_row_hash);

  DELETE FROM public."admin_audit_log"
    WHERE "realm_id" = p_realm_id AND "seq" <= p_through_seq;
  GET DIAGNOSTICS v_deleted = ROW_COUNT;

  RETURN v_deleted;
END;
$$;--> statement-breakpoint
REVOKE ALL ON FUNCTION "admin_audit_log_prune"(uuid, bigint) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON TABLE "admin_audit_log", "admin_audit_log_checkpoints" FROM PUBLIC;
