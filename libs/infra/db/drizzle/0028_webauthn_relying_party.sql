ALTER TABLE "oauth_clients" ADD COLUMN "webauthn_allowed_origins" jsonb DEFAULT '[]'::jsonb NOT NULL;--> statement-breakpoint
ALTER TABLE "realms" ADD COLUMN "webauthn_rp_id" varchar(253);--> statement-breakpoint
ALTER TABLE "oauth_clients" ADD CONSTRAINT "oauth_clients_webauthn_allowed_origins_is_array" CHECK (jsonb_typeof("oauth_clients"."webauthn_allowed_origins") = 'array');--> statement-breakpoint
ALTER TABLE "realms" ADD CONSTRAINT "realms_webauthn_rp_id_normalised" CHECK ("realms"."webauthn_rp_id" ~ '^[a-z0-9_-]+(\.[a-z0-9_-]+)*$' and "realms"."webauthn_rp_id" !~ '^[0-9.]+$');--> statement-breakpoint
-- Hand-written below this line: drizzle-kit does not model functions or
-- triggers, so `db:generate` neither writes nor drops them.
--
-- A realm's passkey RP ID is locked once its first passkey is enrolled
-- (ADR-019 Decision 2, #467). The enrolment writes it where it is NULL; every
-- later change is refused here, whoever writes it, because another RP ID would
-- orphan every passkey enrolled under this one.
CREATE FUNCTION "realms_webauthn_rp_id_permanent"() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'realms.webauthn_rp_id is permanent once set'
    USING ERRCODE = 'check_violation',
          CONSTRAINT = 'realms_webauthn_rp_id_permanent',
          DETAIL = format('realm %s', OLD."id"),
          HINT = 'The RP ID is locked by the realm''s first passkey enrolment. Another RP ID would orphan every enrolled passkey.';
END;
$$;--> statement-breakpoint
CREATE TRIGGER "realms_webauthn_rp_id_permanent"
  BEFORE UPDATE ON "realms"
  FOR EACH ROW
  WHEN (OLD."webauthn_rp_id" IS NOT NULL AND NEW."webauthn_rp_id" IS DISTINCT FROM OLD."webauthn_rp_id")
  EXECUTE FUNCTION "realms_webauthn_rp_id_permanent"();
