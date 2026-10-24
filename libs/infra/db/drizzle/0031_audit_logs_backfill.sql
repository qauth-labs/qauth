-- #458 (ADR-019 Decision 8): copy every audit_logs row into the event store.
--
-- From this release the auth server records events through emitUserEvent
-- and writes no audit row. audit_logs stays in place, read-only; a contract
-- migration drops it after one release. This file only reads it.
--
-- Each row becomes one event:
--   type      the registered type the old event string maps to (the map is
--             LEGACY_EVENT_MAP of @qauth-labs/shared-events; a unit test keeps
--             the VALUES list below equal to it). A row whose string is not in
--             the map is left out: it stays readable in audit_logs.
--   category  the type's own, as the registry fixes it: 'user' for every type
--             but the two an operator tool writes (client.suspended,
--             client.suspension_lifted), which are 'admin'.
--   id        the row's id when it is a UUIDv7, which every row written since
--             the uuidv7() default is. An older row's id gets the row's
--             created_at as its timestamp and keeps its other bits, so the
--             copy is the same on every run.
--   time      created_at, unchanged.
--   realm     the realm of the row's user, else of its client, else the realm
--             its metadata names, else the default realm: the operator realm,
--             or the oldest realm when none is marked yet.
--   subject   the user, the client (its client_id) or the API key, as the
--             type's subject is.
--   client    the client_id of the row's client.
--   actor     the agent client the row names (actor_client_id), with its
--             delegation chain; the developer of a client or API key change;
--             the operator tool of a suspension. No actor otherwise.
--   request   the IP address (an IPv4-mapped address in its IPv4 form) and the
--             User-Agent. No trace id: audit rows kept none.
--   data      the members the type declares, taken from metadata when the old
--             value has the declared form; the members the old string implies
--             (method, form, registration); and for a required member the row
--             cannot supply, a fixed value: 'unknown' for a code, false for a
--             flag, an empty list, 0 for a count, the nil UUID for an id. The
--             rest of metadata is not copied: addresses, session ids, exception
--             messages and token subjects stay in audit_logs.
--
-- ON CONFLICT DO NOTHING on the event id makes the copy safe to run again,
-- so the contract migration can copy rows a previous release wrote after this
-- one ran, before it drops the table.
--
-- The helper functions live in pg_temp: they exist only for this migration's
-- session and are dropped at the end.
CREATE FUNCTION pg_temp.qauth_code(value jsonb) RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    WHEN jsonb_typeof(value) = 'string' AND (value #>> '{}') ~ '^[a-z][a-z0-9_]{0,63}$'
    THEN value #>> '{}'
  END
$$;
--> statement-breakpoint
CREATE FUNCTION pg_temp.qauth_text(value jsonb, max_length integer) RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    WHEN jsonb_typeof(value) = 'string'
      AND length(value #>> '{}') BETWEEN 1 AND max_length
    THEN value #>> '{}'
  END
$$;
--> statement-breakpoint
CREATE FUNCTION pg_temp.qauth_int(value jsonb, low bigint, high bigint) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    WHEN jsonb_typeof(value) = 'number'
      AND (value #>> '{}')::numeric = trunc((value #>> '{}')::numeric)
      AND (value #>> '{}')::numeric BETWEEN low AND high
    THEN to_jsonb((value #>> '{}')::numeric::bigint)
  END
$$;
--> statement-breakpoint
CREATE FUNCTION pg_temp.qauth_bool(value jsonb) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE WHEN jsonb_typeof(value) = 'boolean' THEN value END
$$;
--> statement-breakpoint
CREATE FUNCTION pg_temp.qauth_uuid(value jsonb) RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    WHEN jsonb_typeof(value) = 'string'
      AND (value #>> '{}') ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    THEN lower(value #>> '{}')
  END
$$;
--> statement-breakpoint
-- A list of strings: a JSON array, or a space-delimited string (how a scope
-- was recorded). Items that are not strings of 1 to max_length characters are
-- dropped, and at most max_items are kept. NULL when the value is neither.
CREATE FUNCTION pg_temp.qauth_strings(value jsonb, max_length integer, max_items integer) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    WHEN jsonb_typeof(value) IN ('array', 'string') THEN coalesce(
      (
        SELECT jsonb_agg(item ORDER BY ordinal)
        FROM (
          SELECT item, ordinal
          FROM (
            SELECT element #>> '{}' AS item, ordinal
            FROM jsonb_array_elements(CASE WHEN jsonb_typeof(value) = 'array' THEN value ELSE '[]'::jsonb END)
              WITH ORDINALITY AS listed(element, ordinal)
            WHERE jsonb_typeof(element) = 'string'
            UNION ALL
            SELECT item, ordinal
            FROM regexp_split_to_table(CASE WHEN jsonb_typeof(value) = 'string' THEN value #>> '{}' ELSE '' END, '\s+')
              WITH ORDINALITY AS split(item, ordinal)
          ) AS candidates
          WHERE length(item) BETWEEN 1 AND max_length
          ORDER BY ordinal
          LIMIT max_items
        ) AS kept
      ),
      '[]'::jsonb
    )
  END
$$;
--> statement-breakpoint
-- The grant_type of a token request. Audit rows wrote the two extension
-- grants by a short name; an event carries the registered URN.
CREATE FUNCTION pg_temp.qauth_grant_type(value jsonb) RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE pg_temp.qauth_text(value, 255)
    WHEN 'token-exchange' THEN 'urn:ietf:params:oauth:grant-type:token-exchange'
    WHEN 'jwt-bearer' THEN 'urn:ietf:params:oauth:grant-type:jwt-bearer'
    ELSE pg_temp.qauth_text(value, 255)
  END
$$;
--> statement-breakpoint
-- Why a sign-in failed: the code the row recorded, else the code the two
-- messages the password sign-in wrote stand for.
CREATE FUNCTION pg_temp.qauth_sign_in_reason(metadata jsonb) RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT coalesce(
    pg_temp.qauth_code(metadata -> 'reason'),
    CASE metadata ->> 'error'
      WHEN 'Invalid credentials' THEN 'invalid_credentials'
      WHEN 'Email address not verified' THEN 'email_not_verified'
    END,
    pg_temp.qauth_code(metadata -> 'error'),
    'unknown'
  )
$$;
--> statement-breakpoint
-- The event's data: the members the type declares, from the old metadata.
CREATE FUNCTION pg_temp.qauth_event_data(type text, md jsonb, scope_mode text) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
  SELECT jsonb_strip_nulls(CASE type
    WHEN 'urn:qauth:event:user.signed_in:v1-rc.0' THEN jsonb_build_object(
      'verifierProfile', pg_temp.qauth_text(md -> 'verifierProfile', 64))
    WHEN 'urn:qauth:event:user.sign_in_failed:v1-rc.0' THEN jsonb_build_object(
      'reason', pg_temp.qauth_sign_in_reason(md),
      'verifierProfile', pg_temp.qauth_text(md -> 'verifierProfile', 64))
    WHEN 'urn:qauth:event:user.sign_out_failed:v1-rc.0' THEN jsonb_build_object(
      'reason', coalesce(pg_temp.qauth_code(md -> 'reason'), pg_temp.qauth_code(md -> 'error'), 'unknown'))
    WHEN 'urn:qauth:event:authorization.failed:v1-rc.0' THEN jsonb_build_object(
      'error', coalesce(pg_temp.qauth_code(md -> 'error'), 'unknown'),
      'reason', pg_temp.qauth_code(md -> 'reason'))
    WHEN 'urn:qauth:event:step_up.required:v1-rc.0' THEN jsonb_build_object(
      'reason', coalesce(pg_temp.qauth_code(md -> 'reason'), 'unknown'),
      'error', pg_temp.qauth_code(md -> 'error'),
      'elevatedScopes', pg_temp.qauth_strings(md -> 'elevated', 255, 256),
      'dangerousScopes', pg_temp.qauth_strings(md -> 'dangerous', 255, 256),
      'prompt', pg_temp.qauth_text(md -> 'prompt', 64),
      'maxAge', pg_temp.qauth_int(md -> 'maxAge', 0, 9007199254740991))
    WHEN 'urn:qauth:event:step_up.elevated:v1-rc.0' THEN jsonb_build_object(
      'scopes', coalesce(pg_temp.qauth_strings(md -> 'scopes', 255, 256), '[]'::jsonb),
      'dangerousScopes', coalesce(pg_temp.qauth_strings(md -> 'dangerousScopes', 255, 256), '[]'::jsonb),
      'scopeMode', scope_mode,
      'authenticatedAt', CASE WHEN pg_temp.qauth_int(md -> 'authTime', 0, 253402300799999) IS NOT NULL
        THEN to_char(to_timestamp((md ->> 'authTime')::numeric / 1000) AT TIME ZONE 'UTC',
          'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
      END)
    WHEN 'urn:qauth:event:consent.granted:v1-rc.0' THEN jsonb_build_object(
      'scopes', coalesce(pg_temp.qauth_strings(md -> 'scopes', 255, 256), '[]'::jsonb),
      'remembered', coalesce(pg_temp.qauth_bool(md -> 'remembered'), 'false'::jsonb),
      'dangerousScopes', pg_temp.qauth_strings(md -> 'dangerousScopes', 255, 256))
    WHEN 'urn:qauth:event:consent.denied:v1-rc.0' THEN jsonb_build_object(
      'error', pg_temp.qauth_code(md -> 'error'),
      'reason', pg_temp.qauth_code(md -> 'reason'))
    WHEN 'urn:qauth:event:consent.revoked:v1-rc.0' THEN jsonb_build_object(
      'consentId', coalesce(pg_temp.qauth_uuid(md -> 'consentId'), '00000000-0000-0000-0000-000000000000'),
      'revokedRefreshCount', pg_temp.qauth_int(md -> 'refreshTokensRevoked', 0, 1000000))
    WHEN 'urn:qauth:event:token.issued:v1-rc.0' THEN jsonb_build_object(
      'grantType', coalesce(pg_temp.qauth_grant_type(md -> 'grantType'), 'unknown'),
      'scopes', coalesce(pg_temp.qauth_strings(md -> 'scopes', 255, 256), pg_temp.qauth_strings(md -> 'scope', 255, 256)),
      'audience', pg_temp.qauth_strings(md -> 'audience', 2048, 64),
      'resources', pg_temp.qauth_strings(md -> 'resource', 2048, 64),
      'expiresIn', pg_temp.qauth_int(md -> 'expiresIn', 0, 9007199254740991),
      'issuedTokenType', pg_temp.qauth_text(md -> 'issuedTokenType', 255),
      'refreshFamilyId', pg_temp.qauth_uuid(md -> 'familyId'),
      'delegationDepth', pg_temp.qauth_int(md -> 'delegationDepth', 0, 16),
      'idJagId', pg_temp.qauth_text(md -> 'idJagId', 255),
      'idJagIssuer', pg_temp.qauth_text(md -> 'idJagIssuer', 2048),
      'scopeMode', scope_mode)
    WHEN 'urn:qauth:event:token.request_failed:v1-rc.0' THEN jsonb_build_object(
      'grantType', pg_temp.qauth_grant_type(md -> 'grantType'),
      'error', coalesce(pg_temp.qauth_code(md -> 'error'), 'unknown'),
      'reason', pg_temp.qauth_code(md -> 'reason'))
    WHEN 'urn:qauth:event:token.revoked:v1-rc.0' THEN jsonb_build_object(
      'typeHint', pg_temp.qauth_text(md -> 'tokenTypeHint', 64))
    WHEN 'urn:qauth:event:token.introspected:v1-rc.0' THEN jsonb_build_object(
      'tokenClientId', pg_temp.qauth_text(md -> 'tokenClientId', 255))
    WHEN 'urn:qauth:event:client.created:v1-rc.0' THEN jsonb_build_object(
      'isPublic', coalesce(pg_temp.qauth_bool(md -> 'isPublic'), 'false'::jsonb),
      'isAgent', pg_temp.qauth_bool(md -> 'isAgent'),
      'grantTypes', coalesce(pg_temp.qauth_strings(md -> 'grantTypes', 255, 32), '[]'::jsonb),
      'scopes', pg_temp.qauth_strings(md -> 'scopes', 255, 256),
      'authMethod', coalesce(
        pg_temp.qauth_text(md -> 'tokenEndpointAuthMethod', 64),
        pg_temp.qauth_text(md -> 'authMethod', 64)))
    WHEN 'urn:qauth:event:client.updated:v1-rc.0' THEN jsonb_build_object(
      'fields', coalesce(pg_temp.qauth_strings(md -> 'fields', 64, 64), '[]'::jsonb))
    WHEN 'urn:qauth:event:wallet.linked:v1-rc.0' THEN jsonb_build_object(
      'credentialId', coalesce(pg_temp.qauth_text(md -> 'credentialId', 255), 'unknown'),
      'subjectSource', coalesce(pg_temp.qauth_text(md -> 'subjectSource', 64), 'unknown'),
      'rebound', coalesce(pg_temp.qauth_bool(md -> 'rebound'), 'false'::jsonb),
      'verifierProfile', coalesce(pg_temp.qauth_text(md -> 'verifierProfile', 64), 'unknown'))
    WHEN 'urn:qauth:event:wallet.link_failed:v1-rc.0' THEN jsonb_build_object(
      'reason', coalesce(pg_temp.qauth_code(md -> 'reason'), 'unknown'),
      'verifierProfile', pg_temp.qauth_text(md -> 'verifierProfile', 64))
    WHEN 'urn:qauth:event:wallet.presentation_received:v1-rc.0' THEN jsonb_build_object(
      'verifierProfile', coalesce(pg_temp.qauth_text(md -> 'verifierProfile', 64), 'unknown'),
      'presentationCount', coalesce(pg_temp.qauth_int(md -> 'presentationCount', 0, 1000000), '0'::jsonb))
    WHEN 'urn:qauth:event:token.revocation_failed:v1-rc.0' THEN jsonb_build_object(
      'error', coalesce(pg_temp.qauth_code(md -> 'error'), 'unknown'),
      'reason', pg_temp.qauth_code(md -> 'reason'))
    WHEN 'urn:qauth:event:token.introspection_failed:v1-rc.0' THEN jsonb_build_object(
      'error', coalesce(pg_temp.qauth_code(md -> 'error'), 'unknown'),
      'reason', pg_temp.qauth_code(md -> 'reason'))
    WHEN 'urn:qauth:event:userinfo.request_failed:v1-rc.0' THEN jsonb_build_object(
      'error', coalesce(pg_temp.qauth_code(md -> 'error'), 'unknown'),
      'reason', pg_temp.qauth_code(md -> 'reason'))
    ELSE '{}'::jsonb
  END)
$$;
--> statement-breakpoint
-- An address in the form the event contract publishes: an IPv4-mapped IPv6
-- address in its IPv4 form, NULL when it is in no address form at all.
CREATE FUNCTION pg_temp.qauth_ip(value text) RETURNS text LANGUAGE sql STABLE AS $$
  SELECT CASE
    WHEN value ~* '^::ffff:\d{1,3}(\.\d{1,3}){3}$' AND pg_input_is_valid(substr(value, 8), 'inet')
    THEN host(substr(value, 8)::inet)
    WHEN value !~ '/' AND pg_input_is_valid(value, 'inet') THEN host(value::inet)
  END
$$;
--> statement-breakpoint
WITH legacy_map(event, type, category, implied, subject_type) AS (
  VALUES
  ('user.login.success', 'urn:qauth:event:user.signed_in:v1-rc.0', 'user', '{"method":"password"}'::jsonb, 'user'),
  ('user.login.failure', 'urn:qauth:event:user.sign_in_failed:v1-rc.0', 'user', '{"method":"password"}'::jsonb, 'user'),
  ('ui.login.success', 'urn:qauth:event:user.signed_in:v1-rc.0', 'user', '{"method":"password"}'::jsonb, 'user'),
  ('ui.login.failure', 'urn:qauth:event:user.sign_in_failed:v1-rc.0', 'user', '{"method":"password"}'::jsonb, 'user'),
  ('ui.login.csrf_failure', 'urn:qauth:event:request.csrf_rejected:v1-rc.0', 'user', '{"form":"sign_in"}'::jsonb, 'user'),
  ('ui.wallet_login.success', 'urn:qauth:event:user.signed_in:v1-rc.0', 'user', '{"method":"wallet"}'::jsonb, 'user'),
  ('ui.wallet_login.failure', 'urn:qauth:event:user.sign_in_failed:v1-rc.0', 'user', '{"method":"wallet"}'::jsonb, 'user'),
  ('ui.wallet_login.csrf_failure', 'urn:qauth:event:request.csrf_rejected:v1-rc.0', 'user', '{"form":"wallet_sign_in"}'::jsonb, 'user'),
  ('user.logout.success', 'urn:qauth:event:user.signed_out:v1-rc.0', 'user', '{}'::jsonb, 'user'),
  ('user.logout.failure', 'urn:qauth:event:user.sign_out_failed:v1-rc.0', 'user', '{}'::jsonb, 'user'),
  ('oauth.authorize.success', 'urn:qauth:event:authorization.completed:v1-rc.0', 'user', '{}'::jsonb, 'user'),
  ('oauth.authorize.failure', 'urn:qauth:event:authorization.failed:v1-rc.0', 'user', '{}'::jsonb, 'user'),
  ('oauth.stepup.required', 'urn:qauth:event:step_up.required:v1-rc.0', 'user', '{}'::jsonb, 'user'),
  ('oauth.stepup.elevation', 'urn:qauth:event:step_up.elevated:v1-rc.0', 'user', '{}'::jsonb, 'user'),
  ('oauth.consent.granted', 'urn:qauth:event:consent.granted:v1-rc.0', 'user', '{}'::jsonb, 'user'),
  ('oauth.consent.denied', 'urn:qauth:event:consent.denied:v1-rc.0', 'user', '{}'::jsonb, 'user'),
  ('oauth.consent.revoked', 'urn:qauth:event:consent.revoked:v1-rc.0', 'user', '{}'::jsonb, 'user'),
  ('oauth.consent.csrf_failure', 'urn:qauth:event:request.csrf_rejected:v1-rc.0', 'user', '{"form":"consent"}'::jsonb, 'user'),
  ('consents.revoke.csrf_failure', 'urn:qauth:event:request.csrf_rejected:v1-rc.0', 'user', '{"form":"consent_revocation"}'::jsonb, 'user'),
  ('oauth.token.exchange.success', 'urn:qauth:event:token.issued:v1-rc.0', 'user', '{}'::jsonb, 'user'),
  ('oauth.token.exchange.failure', 'urn:qauth:event:token.request_failed:v1-rc.0', 'user', '{}'::jsonb, 'user'),
  ('oauth.revoke.success', 'urn:qauth:event:token.revoked:v1-rc.0', 'user', '{}'::jsonb, 'user'),
  ('oauth.revoke.failure', 'urn:qauth:event:token.revocation_failed:v1-rc.0', 'user', '{}'::jsonb, NULL),
  ('oauth.introspect.success', 'urn:qauth:event:token.introspected:v1-rc.0', 'user', '{}'::jsonb, 'user'),
  ('oauth.introspect.failure', 'urn:qauth:event:token.introspection_failed:v1-rc.0', 'user', '{}'::jsonb, 'user'),
  ('oauth.userinfo.success', 'urn:qauth:event:userinfo.served:v1-rc.0', 'user', '{}'::jsonb, 'user'),
  ('oauth.userinfo.failure', 'urn:qauth:event:userinfo.request_failed:v1-rc.0', 'user', '{}'::jsonb, 'user'),
  ('oauth.client.registered', 'urn:qauth:event:client.created:v1-rc.0', 'user', '{"registration":"dynamic"}'::jsonb, 'client'),
  ('oauth.client.created', 'urn:qauth:event:client.created:v1-rc.0', 'user', '{"registration":"developer_api"}'::jsonb, 'client'),
  ('oauth.client.updated', 'urn:qauth:event:client.updated:v1-rc.0', 'user', '{}'::jsonb, 'client'),
  ('oauth.client.deleted', 'urn:qauth:event:client.deleted:v1-rc.0', 'user', '{}'::jsonb, 'client'),
  ('oauth.client.secret_regenerated', 'urn:qauth:event:client.secret_rotated:v1-rc.0', 'user', '{}'::jsonb, 'client'),
  ('oauth.client.suspended', 'urn:qauth:event:client.suspended:v1-rc.0', 'admin', '{}'::jsonb, 'client'),
  ('oauth.client.suspension_lifted', 'urn:qauth:event:client.suspension_lifted:v1-rc.0', 'admin', '{}'::jsonb, 'client'),
  ('api_key.created', 'urn:qauth:event:api_key.created:v1-rc.0', 'user', '{}'::jsonb, 'api_key'),
  ('api_key.revoked', 'urn:qauth:event:api_key.revoked:v1-rc.0', 'user', '{}'::jsonb, 'api_key'),
  ('auth.wallet_link.success', 'urn:qauth:event:wallet.linked:v1-rc.0', 'user', '{}'::jsonb, 'user'),
  ('auth.wallet_link.failure', 'urn:qauth:event:wallet.link_failed:v1-rc.0', 'user', '{}'::jsonb, 'user'),
  ('auth.wallet_link.csrf_failure', 'urn:qauth:event:request.csrf_rejected:v1-rc.0', 'user', '{"form":"wallet_link"}'::jsonb, 'user'),
  ('oid4vp.response.received', 'urn:qauth:event:wallet.presentation_received:v1-rc.0', 'user', '{}'::jsonb, NULL)
),
default_realm AS (
  SELECT coalesce(
    (SELECT "id" FROM "realms" WHERE "is_operator" LIMIT 1),
    (SELECT "id" FROM "realms" ORDER BY "created_at", "id" LIMIT 1)
  ) AS "id"
),
source AS (
  SELECT
    a."id" AS "audit_id",
    a."created_at",
    a."user_id",
    a."event",
    a."ip_address",
    a."user_agent",
    a."actor_client_id",
    a."delegation_chain",
    a."scope_mode"::text AS "scope_mode",
    coalesce(a."metadata", '{}'::jsonb) AS "md",
    m."type",
    m."category",
    m."implied",
    m."subject_type",
    coalesce(
      c."client_id",
      pg_temp.qauth_text(a."metadata" -> 'client_id', 255),
      pg_temp.qauth_text(a."metadata" -> 'clientId', 255)
    ) AS "public_client_id",
    coalesce(u."realm_id", c."realm_id", named."id", d."id") AS "realm_id",
    replace(a."id"::text, '-', '') AS "hex"
  FROM "audit_logs" a
  JOIN legacy_map m ON m."event" = a."event"
  LEFT JOIN "users" u ON u."id" = a."user_id"
  LEFT JOIN "oauth_clients" c ON c."id" = a."oauth_client_id"
  LEFT JOIN "realms" named ON named."id"::text = (a."metadata" ->> 'realmId')
  CROSS JOIN default_realm d
)
INSERT INTO "events" (
  "id", "realm_id", "category", "type", "time",
  "actor_type", "actor_id", "actor_delegation_chain",
  "subject_type", "subject_id", "client_id",
  "request_id", "request_ip", "request_user_agent",
  "data", "schema_version"
)
SELECT
  CASE
    WHEN uuid_extract_version(s."audit_id") = 7 THEN s."audit_id"
    ELSE (lpad(to_hex(s."created_at"), 12, '0') || '7' || substr(s."hex", 14, 3) || '8'
      || substr(s."hex", 18, 3) || substr(s."hex", 21, 12))::uuid
  END,
  s."realm_id",
  s."category",
  s."type",
  s."created_at",
  actor."type",
  actor."id",
  actor."chain",
  subject."type",
  subject."id",
  s."public_client_id",
  NULL,
  pg_temp.qauth_ip(s."ip_address"),
  left(s."user_agent", 1024),
  s."implied" || pg_temp.qauth_event_data(s."type", s."md", s."scope_mode"),
  1
FROM source s
CROSS JOIN LATERAL (
  SELECT
    CASE
      WHEN s."actor_client_id" IS NOT NULL THEN 'client'
      WHEN s."subject_type" IN ('client', 'api_key') AND s."user_id" IS NOT NULL THEN 'user'
      WHEN s."category" = 'admin' THEN 'operator_cli'
    END AS "type",
    CASE
      WHEN s."actor_client_id" IS NOT NULL THEN s."actor_client_id"
      WHEN s."subject_type" IN ('client', 'api_key') AND s."user_id" IS NOT NULL THEN s."user_id"::text
    END AS "id",
    CASE
      WHEN s."actor_client_id" IS NOT NULL
        AND jsonb_typeof(s."delegation_chain") = 'array'
        AND jsonb_array_length(s."delegation_chain") BETWEEN 1 AND 16
      THEN s."delegation_chain"
    END AS "chain"
) AS actor
CROSS JOIN LATERAL (
  SELECT
    CASE WHEN subject_id IS NOT NULL THEN s."subject_type" END AS "type",
    subject_id AS "id"
  FROM (
    SELECT CASE s."subject_type"
      WHEN 'user' THEN s."user_id"::text
      WHEN 'client' THEN s."public_client_id"
      WHEN 'api_key' THEN pg_temp.qauth_text(s."md" -> 'apiKeyId', 255)
    END AS subject_id
  ) AS picked
) AS subject
WHERE s."realm_id" IS NOT NULL
ORDER BY s."created_at", s."audit_id"
ON CONFLICT ("id") DO NOTHING;
--> statement-breakpoint
DROP FUNCTION pg_temp.qauth_ip(text);
--> statement-breakpoint
DROP FUNCTION pg_temp.qauth_event_data(text, jsonb, text);
--> statement-breakpoint
DROP FUNCTION pg_temp.qauth_sign_in_reason(jsonb);
--> statement-breakpoint
DROP FUNCTION pg_temp.qauth_grant_type(jsonb);
--> statement-breakpoint
DROP FUNCTION pg_temp.qauth_strings(jsonb, integer, integer);
--> statement-breakpoint
DROP FUNCTION pg_temp.qauth_uuid(jsonb);
--> statement-breakpoint
DROP FUNCTION pg_temp.qauth_bool(jsonb);
--> statement-breakpoint
DROP FUNCTION pg_temp.qauth_int(jsonb, bigint, bigint);
--> statement-breakpoint
DROP FUNCTION pg_temp.qauth_text(jsonb, integer);
--> statement-breakpoint
DROP FUNCTION pg_temp.qauth_code(jsonb);
