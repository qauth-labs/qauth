-- #507 (ADR-019 Decision 7): the `qauth:` scope namespace is QAuth's own, the
-- admin API's scopes (`qauth:admin:read`, `qauth:admin:write`,
-- `qauth:admin:security`) among them, so a realm's dynamic registration
-- allowlist may not hold a scope in it, whatever the case of its ASCII
-- letters. Other servers' scopes such as `admin:org` are ordinary scopes and
-- stay where they are.
--
-- An empty allowlist is not "no scope": the server reads it as not set and
-- fills it from DEFAULT_DYNAMIC_REGISTRATION_SCOPES at the realm's next
-- registration. Removing the `qauth:` entries from a list that holds nothing
-- else would therefore widen what the realm allows, and so would emptying a
-- value that is not a list. Both stop the migration instead, naming the
-- realms, before anything is changed; the operator sets those lists by hand
-- and runs the migrations again.
DO $$
DECLARE
  blocked text;
BEGIN
  SELECT string_agg(format('%s (%s)', "name", "id"), ', ' ORDER BY "name")
  INTO blocked
  FROM "realms"
  WHERE jsonb_path_exists("dynamic_registration_allowed_scopes", '$[*] ? (@ like_regex "^[qQ][aA][uU][tT][hH]:")')
    AND (
      jsonb_typeof("dynamic_registration_allowed_scopes") <> 'array'
      OR NOT EXISTS (
        SELECT 1
        FROM jsonb_array_elements("dynamic_registration_allowed_scopes") AS entry("scope")
        WHERE NOT jsonb_path_exists(entry."scope", '$ ? (@ like_regex "^[qQ][aA][uU][tT][hH]:")')
      )
    );
  IF blocked IS NOT NULL THEN
    RAISE EXCEPTION 'migration 0040: the dynamic registration allowlist of realm % holds no scope outside the reserved "qauth:" namespace, or is not a list; removing those scopes would leave it empty, which the server fills from DEFAULT_DYNAMIC_REGISTRATION_SCOPES', blocked
      USING HINT = 'Set each named realm''s dynamic_registration_allowed_scopes to the JSON list of scopes dynamic registration should allow, with no "qauth:" scope, for example UPDATE realms SET dynamic_registration_allowed_scopes = ''["openid"]''::jsonb WHERE id = ''<id>''; then run the migrations again.';
  END IF;
END
$$;
--> statement-breakpoint
-- Every other realm whose allowlist names a `qauth:` scope loses those
-- entries and keeps the others in their order. Clients that already hold such
-- a scope keep it: this touches the realm's allowlist only.
UPDATE "realms"
SET
  "dynamic_registration_allowed_scopes" = (
    SELECT coalesce(jsonb_agg(entry."scope" ORDER BY entry."position"), '[]'::jsonb)
    FROM jsonb_array_elements("realms"."dynamic_registration_allowed_scopes")
      WITH ORDINALITY AS entry("scope", "position")
    WHERE NOT jsonb_path_exists(entry."scope", '$ ? (@ like_regex "^[qQ][aA][uU][tT][hH]:")')
  ),
  "updated_at" = (EXTRACT(EPOCH FROM NOW())::bigint * 1000)
WHERE jsonb_typeof("dynamic_registration_allowed_scopes") = 'array'
  AND jsonb_path_exists("dynamic_registration_allowed_scopes", '$[*] ? (@ like_regex "^[qQ][aA][uU][tT][hH]:")');
--> statement-breakpoint
ALTER TABLE "realms" ADD CONSTRAINT "realms_dynamic_registration_scopes_not_qauth" CHECK (NOT jsonb_path_exists("realms"."dynamic_registration_allowed_scopes", '$[*] ? (@ like_regex "^[qQ][aA][uU][tT][hH]:")'));
