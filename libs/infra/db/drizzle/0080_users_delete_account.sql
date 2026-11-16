-- #681: an admin deletes an account of a realm through the admin API's
-- security operation `users.delete`. It runs as the admin role's database
-- user (ADR-019 Decision 7), which reads `users` and writes none of it: no role
-- deletes an account through a table grant (the grants map holds that). Two
-- functions give the operation what it needs and no more. Nothing runs now:
-- the migration only creates them, so it rewrites no row and a release before
-- this one never names them.
--
-- users_lock_for_deletion: lock the account of the realm FOR UPDATE, in the
-- caller's transaction, and return its id; no row for an account the realm
-- does not hold. FOR UPDATE, not a weaker lock, because only it conflicts with
-- the key-share lock a foreign key takes: from the lock to the commit, nothing
-- adds a session, a token, a code, a credential, a consent or an admin grant
-- of the account, so every session the deletion removes is one the operation
-- ended first, with its back-channel logout notices, in the same
-- transaction. A locking clause needs the UPDATE privilege the admin role does
-- not hold on `users`, so the lock is taken here, as the owner; the lock is the
-- transaction's and is held until it ends.
--
-- users_delete_account: delete the account of the realm and, through the
-- schema's cascades, everything that hangs off it (credentials, recovery
-- codes, consents, attributes, sessions with their clients, refresh tokens,
-- authorization codes, required actions, the session epoch). Its own guard,
-- whoever calls it: never a service account's account (marked, or bound by a
-- `service_accounts` row), never one that holds an admin grant not revoked; it
-- deletes nothing then. It returns the deleted id, or no row.
--
-- Both are SECURITY DEFINER: they read and write the tables as their owner.
-- Their search_path is pinned and EXECUTE is revoked from PUBLIC; the per-role
-- grants give them to the admin role alone.
CREATE FUNCTION "users_lock_for_deletion"(p_realm_id uuid, p_user_id uuid)
RETURNS TABLE ("id" uuid)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT u."id"
    FROM public."users" u
   WHERE u."realm_id" = p_realm_id
     AND u."id" = p_user_id
     FOR UPDATE
$$;--> statement-breakpoint
REVOKE ALL ON FUNCTION "users_lock_for_deletion"(uuid, uuid) FROM PUBLIC;--> statement-breakpoint
CREATE FUNCTION "users_delete_account"(p_realm_id uuid, p_user_id uuid)
RETURNS TABLE ("id" uuid)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  DELETE FROM public."users" u
   WHERE u."realm_id" = p_realm_id
     AND u."id" = p_user_id
     AND NOT u."is_service_account"
     AND NOT EXISTS (
       SELECT 1 FROM public."service_accounts" s WHERE s."user_id" = u."id"
     )
     AND NOT EXISTS (
       SELECT 1 FROM public."admin_grants" g
        WHERE g."user_id" = u."id" AND g."revoked_at" IS NULL
     )
  RETURNING u."id"
$$;--> statement-breakpoint
REVOKE ALL ON FUNCTION "users_delete_account"(uuid, uuid) FROM PUBLIC;
