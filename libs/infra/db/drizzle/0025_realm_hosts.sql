CREATE TYPE "public"."realm_host_kind" AS ENUM('primary', 'endpoint');--> statement-breakpoint
CREATE TABLE "realm_hosts" (
	"host" varchar(253) PRIMARY KEY NOT NULL,
	"realm_id" uuid NOT NULL,
	"kind" realm_host_kind NOT NULL,
	"created_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	CONSTRAINT "realm_hosts_host_normalised" CHECK ("realm_hosts"."host" ~ '^(\[[0-9a-f:.]+\]|[a-z0-9_-]+(\.[a-z0-9_-]+)*)$'),
	CONSTRAINT "realm_hosts_primary_not_ip_literal" CHECK ("realm_hosts"."kind" = 'endpoint' or ("realm_hosts"."host" !~ '^\[' and "realm_hosts"."host" !~ '^[0-9.]+$'))
);
--> statement-breakpoint
ALTER TABLE "realms" ADD COLUMN "issuer" text;--> statement-breakpoint
ALTER TABLE "realms" ADD COLUMN "is_operator" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "realm_hosts" ADD CONSTRAINT "realm_hosts_realm_id_realms_id_fk" FOREIGN KEY ("realm_id") REFERENCES "public"."realms"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "idx_realm_hosts_one_primary" ON "realm_hosts" USING btree ("realm_id") WHERE "realm_hosts"."kind" = 'primary';--> statement-breakpoint
CREATE INDEX "idx_realm_hosts_realm_id" ON "realm_hosts" USING btree ("realm_id");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_realms_one_operator" ON "realms" USING btree ("is_operator") WHERE "realms"."is_operator" = true;--> statement-breakpoint
ALTER TABLE "realms" ADD CONSTRAINT "realms_issuer_unique" UNIQUE("issuer");--> statement-breakpoint
ALTER TABLE "realms" ADD CONSTRAINT "realms_issuer_not_empty" CHECK ("realms"."issuer" <> '');--> statement-breakpoint
ALTER TABLE "realms" ADD CONSTRAINT "realms_issuer_no_trailing_slash" CHECK (right("realms"."issuer", 1) <> '/');--> statement-breakpoint
-- Hand-written below this line: drizzle-kit does not model functions or
-- triggers, so `db:generate` neither writes nor drops them.
--
-- A realm's issuer and primary host are permanent (ADR-019 Decision 1, #470).
-- Both may be set once, from nothing to a value; every later change is
-- refused here, whoever writes it. Rows that predate this migration keep a
-- NULL issuer and no primary host until the boot step fills them (#484).
CREATE FUNCTION "realms_issuer_permanent"() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'realms.issuer is permanent once set'
    USING ERRCODE = 'check_violation',
          CONSTRAINT = 'realms_issuer_permanent',
          DETAIL = format('realm %s', OLD."id"),
          HINT = 'An issuer may only be set where it is NULL. A realm that needs another issuer is a new realm.';
END;
$$;--> statement-breakpoint
CREATE TRIGGER "realms_issuer_permanent"
  BEFORE UPDATE ON "realms"
  FOR EACH ROW
  WHEN (OLD."issuer" IS NOT NULL AND NEW."issuer" IS DISTINCT FROM OLD."issuer")
  EXECUTE FUNCTION "realms_issuer_permanent"();--> statement-breakpoint
CREATE FUNCTION "realm_hosts_primary_permanent"() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  -- Deleting a realm cascades to its hosts. The cascade runs after the realm
  -- row is gone, so that delete passes; any other delete of a primary host
  -- would free the realm to take a second one, and is refused.
  IF TG_OP = 'DELETE' AND NOT EXISTS (SELECT 1 FROM "realms" WHERE "id" = OLD."realm_id") THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'a realm''s primary host is permanent once set'
    USING ERRCODE = 'check_violation',
          CONSTRAINT = 'realm_hosts_primary_permanent',
          DETAIL = format('realm %s, host %s', OLD."realm_id", OLD."host"),
          HINT = 'A primary host may only be added to a realm that has none. Endpoint hosts may be added and removed.';
END;
$$;--> statement-breakpoint
CREATE TRIGGER "realm_hosts_primary_permanent_update"
  BEFORE UPDATE ON "realm_hosts"
  FOR EACH ROW
  WHEN (
    OLD."kind" = 'primary'
    AND (NEW."host", NEW."realm_id", NEW."kind") IS DISTINCT FROM (OLD."host", OLD."realm_id", OLD."kind")
  )
  EXECUTE FUNCTION "realm_hosts_primary_permanent"();--> statement-breakpoint
CREATE TRIGGER "realm_hosts_primary_permanent_delete"
  BEFORE DELETE ON "realm_hosts"
  FOR EACH ROW
  WHEN (OLD."kind" = 'primary')
  EXECUTE FUNCTION "realm_hosts_primary_permanent"();
