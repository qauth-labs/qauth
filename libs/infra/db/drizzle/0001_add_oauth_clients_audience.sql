ALTER TABLE "oauth_clients" ADD COLUMN "audience" jsonb
  CONSTRAINT "oauth_clients_audience_is_array"
    CHECK ("audience" IS NULL OR jsonb_typeof("audience") = 'array');