-- #522: service accounts for the admin API (ADR-019 Decision 7). A service
-- account is a `users` row with no credential, in the operator realm, and the
-- OAuth client it signs in with: `private_key_jwt`, `client_credentials` and a
-- DPoP proof. Its admin grants attach to the user row. This table binds the
-- two, names the account, and says whether it is enabled; the token endpoint
-- and the admin API read it on every request, so a disabled account gets no
-- token and makes no admin call from the next request on.
--
-- The composite foreign key keeps the account in the row's realm
-- (`users_id_realm_id_unique`); one user and one client are one service
-- account's at most. Deleting the realm or the account removes the row. The
-- client is not deleted while the row binds it: its foreign key is checked
-- at the end of the statement (`no action`), so the realm's own cascade,
-- which removes both, passes, and any other deletion of the client fails.
--
-- `users.is_service_account` makes being a service account a lasting fact of
-- the account: set when the account is created, never changed (the trigger
-- `users_service_account_permanent`). The admin API refuses a marked account
-- whose binding is gone, so it is never taken for a person's. The column's
-- constant default needs no rewrite of `users`.
--
-- `service_accounts_end_tokens(realm, client)` moves the `not_valid_before` of
-- the account a client binds to now, so a token issued before the client was
-- suspended stays refused once the suspension lifts. The admin API's
-- `clients.disable` calls it; its role holds no UPDATE on `users`. It is a
-- SECURITY DEFINER function, its search_path pinned, EXECUTE revoked from
-- PUBLIC and given to `admin` by the grants map.
--
-- A new, empty table, a column with a default and two functions: nothing is
-- rewritten, and a release before this one never names them, so it is safe
-- during a rolling upgrade; a node of such a release knows no service account
-- and issues its client no admin token, since that release names no account
-- for a `client_credentials` token. Its INSERT into `users` names no
-- `is_service_account`, and gets the default. Forward-only.
CREATE TABLE "service_accounts" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"realm_id" uuid NOT NULL,
	"name" varchar(64) NOT NULL,
	"user_id" uuid NOT NULL,
	"client_id" uuid NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"created_by" uuid,
	"created_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	CONSTRAINT "service_accounts_realm_name_unique" UNIQUE("realm_id","name"),
	CONSTRAINT "service_accounts_user_id_unique" UNIQUE("user_id"),
	CONSTRAINT "service_accounts_client_id_unique" UNIQUE("client_id"),
	CONSTRAINT "service_accounts_name_grammar" CHECK ("service_accounts"."name" ~ '^[a-z][a-z0-9]*(-[a-z0-9]+)*$')
);
--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "is_service_account" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "service_accounts" ADD CONSTRAINT "service_accounts_realm_id_realms_id_fk" FOREIGN KEY ("realm_id") REFERENCES "public"."realms"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "service_accounts" ADD CONSTRAINT "service_accounts_client_id_oauth_clients_id_fk" FOREIGN KEY ("client_id") REFERENCES "public"."oauth_clients"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "service_accounts" ADD CONSTRAINT "service_accounts_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "service_accounts" ADD CONSTRAINT "service_accounts_user_realm_fk" FOREIGN KEY ("user_id","realm_id") REFERENCES "public"."users"("id","realm_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_service_accounts_created_by" ON "service_accounts" USING btree ("created_by");
--> statement-breakpoint
-- Whether an account is a service account's never changes: an update that
-- names the column with another value is refused, whoever makes it.
CREATE FUNCTION "users_service_account_permanent"() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF NEW."is_service_account" IS DISTINCT FROM OLD."is_service_account" THEN
    RAISE EXCEPTION 'users.is_service_account is set when the account is created, and never changes'
      USING ERRCODE = 'check_violation',
            CONSTRAINT = 'users_service_account_permanent',
            TABLE = 'users';
  END IF;
  RETURN NEW;
END;
$$;
--> statement-breakpoint
CREATE TRIGGER "users_service_account_permanent"
  BEFORE UPDATE OF "is_service_account" ON "users"
  FOR EACH ROW
  EXECUTE FUNCTION "users_service_account_permanent"();
--> statement-breakpoint
-- End every token issued so far to the service account that p_client_id
-- binds in p_realm_id: its account's not_valid_before moves to the database's
-- clock, never back (users_not_valid_before holds that). How many accounts it
-- moved: 0 for a client no service account binds.
CREATE FUNCTION "service_accounts_end_tokens"(p_realm_id uuid, p_client_id uuid)
RETURNS integer
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  WITH ended AS (
    UPDATE public."users" AS u
       SET "not_valid_before" = GREATEST(
             coalesce(u."not_valid_before", 0),
             floor(EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint
           )
      FROM public."service_accounts" AS s
     WHERE s."realm_id" = p_realm_id
       AND s."client_id" = p_client_id
       AND u."id" = s."user_id"
       AND u."realm_id" = s."realm_id"
    RETURNING 1
  )
  SELECT count(*)::integer FROM ended
$$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION "service_accounts_end_tokens"(uuid, uuid) FROM PUBLIC;
