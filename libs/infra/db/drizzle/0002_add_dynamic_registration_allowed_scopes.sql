ALTER TABLE "realms" ADD COLUMN "dynamic_registration_allowed_scopes" jsonb DEFAULT '[]'::jsonb NOT NULL;
