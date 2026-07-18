-- #261: drop the vestigial users.email_verified/email_verified_at columns
-- kept out of 0011's issue-literal scope. No guard needed: since #230 they
-- have no writers, and their only reader surfaced the column DEFAULT (the
-- register 201 response, now a literal). Verified state lives in
-- user_credentials.credential_data.email_verified and user_attributes.verified.
ALTER TABLE "users" DROP COLUMN "email_verified";--> statement-breakpoint
ALTER TABLE "users" DROP COLUMN "email_verified_at";