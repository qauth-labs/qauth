CREATE TYPE "public"."agent_mode" AS ENUM('readonly', 'admin', 'exec');--> statement-breakpoint
ALTER TABLE "oauth_clients" ADD COLUMN "max_agent_mode" "agent_mode";
