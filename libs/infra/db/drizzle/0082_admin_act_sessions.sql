-- #523: act-chain tokens for admins acting for a user (ADR-019 Decision 7).
-- An admin who acts for a user gets an act-chain token (`sub` the user, `act`
-- the admin), minted in the transaction of the approved security operation
-- that issues it; that transaction writes one row here. The account API reads
-- the row on every call made with the token: the token works only while its
-- row is there, unexpired, and its approval is still consumed, and while the
-- admin still holds the permissions the row names. The user's account page
-- lists the rows ("an administrator acted for you").
--
-- The composite foreign key keeps the user in the row's realm
-- (`users_id_realm_id_unique`); deleting the user or the realm removes the
-- rows. The admin's account and the approval are referenced by id only, as
-- the admin audit log does, so the record outlives them. No secret: the row
-- holds the token's `jti`, never the token.
--
-- The account API (`api`) appends the admin audit row of each call made with
-- such a token through the two functions at the end, and holds nothing on
-- admin_audit_log or its checkpoints: it can neither read the log nor write
-- any other row.
--
-- A new, empty table and two new functions: nothing is rewritten, and a
-- release before this one never names them, so it is safe during a rolling
-- upgrade. `admin` may insert and read the table, `api` may read it; no role
-- updates or deletes it. Forward-only. The functions are custom: drizzle-kit
-- models no function.
CREATE TABLE "admin_act_sessions" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"realm_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"admin_realm_id" uuid NOT NULL,
	"admin_user_id" uuid NOT NULL,
	"admin_client_id" varchar(255) NOT NULL,
	"approval_id" uuid NOT NULL,
	"operation_id" varchar(128) NOT NULL,
	"permission_ids" jsonb NOT NULL,
	"token_jti" varchar(255) NOT NULL,
	"scopes" jsonb NOT NULL,
	"created_at" bigint NOT NULL,
	"expires_at" bigint NOT NULL,
	CONSTRAINT "admin_act_sessions_realm_jti_unique" UNIQUE("realm_id","token_jti"),
	CONSTRAINT "admin_act_sessions_admin_client_id_not_empty" CHECK ("admin_act_sessions"."admin_client_id" <> ''),
	CONSTRAINT "admin_act_sessions_operation_id_not_empty" CHECK ("admin_act_sessions"."operation_id" <> ''),
	CONSTRAINT "admin_act_sessions_token_jti_not_empty" CHECK ("admin_act_sessions"."token_jti" <> ''),
	CONSTRAINT "admin_act_sessions_scopes_strings" CHECK (jsonb_typeof("admin_act_sessions"."scopes") = 'array' AND jsonb_array_length("admin_act_sessions"."scopes") > 0 AND NOT jsonb_path_exists("admin_act_sessions"."scopes", '$[*] ? (@.type() != "string")')),
	CONSTRAINT "admin_act_sessions_permission_ids_strings" CHECK (jsonb_typeof("admin_act_sessions"."permission_ids") = 'array' AND jsonb_array_length("admin_act_sessions"."permission_ids") > 0 AND NOT jsonb_path_exists("admin_act_sessions"."permission_ids", '$[*] ? (@.type() != "string")')),
	CONSTRAINT "admin_act_sessions_lifetime" CHECK ("admin_act_sessions"."expires_at" > "admin_act_sessions"."created_at" AND "admin_act_sessions"."expires_at" - "admin_act_sessions"."created_at" <= 600000)
);
--> statement-breakpoint
ALTER TABLE "admin_act_sessions" ADD CONSTRAINT "admin_act_sessions_realm_id_realms_id_fk" FOREIGN KEY ("realm_id") REFERENCES "public"."realms"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "admin_act_sessions" ADD CONSTRAINT "admin_act_sessions_user_realm_fk" FOREIGN KEY ("user_id","realm_id") REFERENCES "public"."users"("id","realm_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_admin_act_sessions_user" ON "admin_act_sessions" USING btree ("realm_id","user_id","created_at");--> statement-breakpoint
-- The chain head the next row of `p_realm_id` follows, under the realm's chain
-- lock: the key appendAdminAudit and admin_audit_log_prune take, from the same
-- expression, held until the transaction ends. The newest row, else the
-- newest checkpoint, else the genesis hash, as the trigger
-- admin_audit_log_follows_head (0026) reads it.
--
-- SECURITY DEFINER: it reads the log as its owner. Its search_path is pinned,
-- every table is named with its schema, and EXECUTE is revoked from PUBLIC;
-- the per-role grants give it to `api`.
CREATE FUNCTION "admin_audit_act_chain_head"(p_realm_id uuid, OUT o_seq bigint, OUT o_row_hash bytea)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended('qauth:admin-audit:' || p_realm_id::text, 0));
  SELECT l."seq", l."row_hash" INTO o_seq, o_row_hash
    FROM public."admin_audit_log" l
   WHERE l."realm_id" = p_realm_id
   ORDER BY l."seq" DESC
   LIMIT 1;
  IF NOT FOUND THEN
    SELECT c."seq", c."row_hash" INTO o_seq, o_row_hash
      FROM public."admin_audit_log_checkpoints" c
     WHERE c."realm_id" = p_realm_id
     ORDER BY c."seq" DESC
     LIMIT 1;
    IF NOT FOUND THEN
      o_seq := 0;
      o_row_hash := decode(repeat('00', 32), 'hex');
    END IF;
  END IF;
END;
$$;--> statement-breakpoint
REVOKE ALL ON FUNCTION "admin_audit_act_chain_head"(uuid) FROM PUBLIC;--> statement-breakpoint
-- The audit row of one call an admin made with the act-chain token
-- `p_token_jti` of `p_realm_id`, returned as stored. Its actor is the admin
-- the token's admin_act_sessions row names, its act chain must be that row's
-- user and admin with the admin's realm issuer and client, and its operation
-- an account API operation, with no effect, diff, approval or request digest.
-- Any other row is not inserted, and the caller gets no row back. The caller
-- hashes the row; the chain triggers of 0026 check its place.
--
-- SECURITY DEFINER: it writes the log as its owner. Its search_path is pinned,
-- every table and type is named with its schema, and EXECUTE is revoked from
-- PUBLIC; the per-role grants give it to `api`.
CREATE FUNCTION "admin_audit_append_act_chain_call"(
  p_realm_id uuid,
  p_token_jti text,
  p_seq bigint,
  p_prev_hash bytea,
  p_row_hash bytea,
  p_operation_id text,
  p_operation_class text,
  p_outcome text,
  p_act_chain jsonb,
  p_trace_id text,
  p_created_at bigint
)
RETURNS SETOF public."admin_audit_log"
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  INSERT INTO public."admin_audit_log" (
    "realm_id", "seq", "prev_hash", "row_hash", "actor_kind", "actor_id", "actor_realm_id",
    "act_chain", "operation_id", "operation_class", "effects", "outcome", "masked_diff",
    "approvals", "request_digest", "trace_id", "created_at"
  )
  SELECT p_realm_id, p_seq, p_prev_hash, p_row_hash, 'human_admin'::public."admin_actor_kind",
         s."admin_user_id"::text, s."admin_realm_id", p_act_chain, p_operation_id,
         p_operation_class::public."admin_operation_class", '[]'::jsonb,
         p_outcome::public."admin_audit_outcome", NULL, '[]'::jsonb, NULL, p_trace_id,
         p_created_at
    FROM public."admin_act_sessions" s
    JOIN public."realms" r ON r."id" = s."admin_realm_id"
   WHERE s."realm_id" = p_realm_id
     AND s."token_jti" = p_token_jti
     AND starts_with(p_operation_id, 'account.')
     AND p_act_chain = jsonb_build_object(
           'sub', s."user_id"::text,
           'act', jsonb_build_object(
             'sub', s."admin_user_id"::text,
             'iss', r."issuer",
             'client_id', s."admin_client_id"
           )
         )
  RETURNING *
$$;--> statement-breakpoint
REVOKE ALL ON FUNCTION "admin_audit_append_act_chain_call"(uuid, text, bigint, bytea, bytea, text, text, text, jsonb, text, bigint) FROM PUBLIC;
