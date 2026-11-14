-- #521: the two-admin rule (ADR-019 Decision 7) reads
-- admin_grants.last_security_change_at to tell an approver whose credentials,
-- identifier or contact address changed in the 7 days before a request from
-- one whose did not, whoever made the change. The account API (`api`), the
-- hosted pages and sign-in flows (`web`) and the admin API (`admin`) record
-- such a change through the function below, in the transaction of the change.
--
-- No role holds UPDATE on admin_grants, and none gets it here: the function
-- moves last_security_change_at of the account's live grants to the
-- database's time, never back (greatest), and touches no other column, so a
-- caller can neither grant, revoke nor change a role, nor set the time
-- itself. It acts only on an account of `p_realm_id`, and returns how many
-- grants it moved: zero for an account that administers nothing. The trigger
-- admin_grants_revoke_only still refuses any other change.
--
-- SECURITY DEFINER: it writes the table as its owner. Its search_path is
-- pinned and EXECUTE is revoked from PUBLIC; the per-role grants give it to
-- `web`, `api` and `admin`. Nothing is rewritten, and a release before this
-- one never calls it: forward-only, safe during a rolling upgrade. Custom:
-- drizzle-kit models no function.
CREATE FUNCTION "admin_grants_record_security_change"(p_realm_id uuid, p_user_id uuid)
RETURNS integer
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  WITH moved AS (
    UPDATE public."admin_grants" g
       SET "last_security_change_at" = greatest(EXTRACT(EPOCH FROM NOW())::bigint * 1000, g."last_security_change_at")
     WHERE g."user_id" = p_user_id
       AND g."revoked_at" IS NULL
       AND EXISTS (
         SELECT 1
           FROM public."users" u
          WHERE u."id" = p_user_id
            AND u."realm_id" = p_realm_id
       )
    RETURNING 1
  )
  SELECT count(*)::integer FROM moved
$$;--> statement-breakpoint
REVOKE ALL ON FUNCTION "admin_grants_record_security_change"(uuid, uuid) FROM PUBLIC;
