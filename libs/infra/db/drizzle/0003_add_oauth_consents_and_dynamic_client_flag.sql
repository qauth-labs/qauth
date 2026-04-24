-- Consent screen support (issue #150)
--
-- Adds the `oauth_consents` table that stores user grants per (user, client),
-- plus a `dynamic_registered_at` column on `oauth_clients` consumed by the
-- consent UI to badge recently-dynamic-registered clients. Null means the
-- client was provisioned via the normal developer flow and is not "new".

CREATE TABLE "oauth_consents" (
  "id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
  "user_id" uuid NOT NULL,
  "oauth_client_id" uuid NOT NULL,
  "realm_id" uuid NOT NULL,
  "scopes" jsonb DEFAULT '[]'::jsonb NOT NULL,
  "granted_at" bigint DEFAULT (EXTRACT(EPOCH FROM now()) * 1000)::bigint NOT NULL,
  "revoked_at" bigint,
  CONSTRAINT "oauth_consents_user_id_users_id_fk"
    FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE,
  CONSTRAINT "oauth_consents_oauth_client_id_oauth_clients_id_fk"
    FOREIGN KEY ("oauth_client_id") REFERENCES "oauth_clients"("id") ON DELETE CASCADE,
  CONSTRAINT "oauth_consents_realm_id_realms_id_fk"
    FOREIGN KEY ("realm_id") REFERENCES "realms"("id") ON DELETE CASCADE
);

-- Partial unique index: one active (non-revoked) consent per (user, client).
CREATE UNIQUE INDEX "idx_oauth_consents_user_client_active"
  ON "oauth_consents" ("user_id", "oauth_client_id")
  WHERE "revoked_at" IS NULL;

CREATE INDEX "idx_oauth_consents_user_id" ON "oauth_consents" ("user_id");
CREATE INDEX "idx_oauth_consents_client_id" ON "oauth_consents" ("oauth_client_id");
CREATE INDEX "idx_oauth_consents_realm_id" ON "oauth_consents" ("realm_id");

ALTER TABLE "oauth_clients"
  ADD COLUMN "dynamic_registered_at" bigint;
