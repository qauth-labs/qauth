-- #434 (ADR-011): the foreign authorization servers and MCP servers a client may
-- name when it mints an ID-JAG, and the resources it may redeem one for, get
-- their own column. Until now both sides read oauth_clients.audience, which also
-- bounds client_credentials, so listing a foreign authorization server for ID-JAG
-- let the client request QAuth access tokens that name it.
--
-- Nothing is copied from audience. ID-JAG is off by default (ID_JAG_ENABLED) and
-- new, and a copy would carry every client_credentials audience over as an ID-JAG
-- target. An empty list denies both sides, so after this migration no client can
-- mint or redeem an ID-JAG until an operator lists its targets in the seed
-- manifest (id_jag_targets).
ALTER TABLE "oauth_clients" ADD COLUMN "id_jag_targets" jsonb DEFAULT '[]'::jsonb NOT NULL;--> statement-breakpoint
ALTER TABLE "oauth_clients" ADD CONSTRAINT "oauth_clients_id_jag_targets_is_array" CHECK (jsonb_typeof("oauth_clients"."id_jag_targets") = 'array');
