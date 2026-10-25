ALTER TABLE "oauth_clients" ADD COLUMN "dpop_bound_access_tokens" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "authorization_codes" ADD COLUMN "dpop_jkt" varchar(43);--> statement-breakpoint
ALTER TABLE "refresh_tokens" ADD COLUMN "cnf_jkt" varchar(43);--> statement-breakpoint
ALTER TABLE "authorization_codes" ADD CONSTRAINT "authorization_codes_dpop_jkt_format" CHECK ("authorization_codes"."dpop_jkt" IS NULL OR "authorization_codes"."dpop_jkt" ~ '^[A-Za-z0-9_-]{43}$');--> statement-breakpoint
ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_cnf_jkt_format" CHECK ("refresh_tokens"."cnf_jkt" IS NULL OR "refresh_tokens"."cnf_jkt" ~ '^[A-Za-z0-9_-]{43}$');