ALTER TYPE "public"."grant_type" ADD VALUE 'urn:ietf:params:oauth:grant-type:jwt-bearer';--> statement-breakpoint
ALTER TABLE "oauth_clients" ADD COLUMN "jwks" jsonb;--> statement-breakpoint
ALTER TABLE "oauth_clients" ADD COLUMN "jwks_uri" text;