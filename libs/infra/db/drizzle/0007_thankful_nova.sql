CREATE TYPE "public"."environment" AS ENUM('development', 'staging', 'production');--> statement-breakpoint
ALTER TABLE "oauth_clients" ADD COLUMN "environment" "environment" DEFAULT 'production' NOT NULL;--> statement-breakpoint
ALTER TABLE "realms" ADD COLUMN "max_environment_laxity" "environment" DEFAULT 'production' NOT NULL;