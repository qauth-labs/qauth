-- #891: the scopes the client_credentials grant may issue to a client, out of
-- its scopes. A client_credentials token names no user, so a client that also
-- signs users in (a relying party that receives SSF events, say) got a token
-- without a user for every scope its users grant it. An operator now lists the
-- scopes the grant may issue (ssf:stream alone, for such a receiver) in the
-- seed manifest's client_credentials_scopes.
--
-- Nullable with no default: NULL leaves the grant as it was, any scope of
-- scopes, for every existing client and for every client the previous release
-- still creates during a rolling upgrade. Nothing is rewritten. The CHECK
-- holds the stored shape (NULL or a JSON array), as for id_jag_targets.
ALTER TABLE "oauth_clients" ADD COLUMN "client_credentials_scopes" jsonb;--> statement-breakpoint
ALTER TABLE "oauth_clients" ADD CONSTRAINT "oauth_clients_client_credentials_scopes_is_array" CHECK ("oauth_clients"."client_credentials_scopes" IS NULL OR jsonb_typeof("oauth_clients"."client_credentials_scopes") = 'array');