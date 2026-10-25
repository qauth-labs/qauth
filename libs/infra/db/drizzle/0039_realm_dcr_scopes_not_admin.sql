-- #507 (ADR-019 Decision 7): the `admin:` scope prefix is reserved for the
-- admin API, so a realm's dynamic registration allowlist may not hold a scope
-- that starts with it, whatever the case of its ASCII letters.
--
-- A realm whose allowlist already names such a scope loses those entries, and
-- keeps the others in their order, before the CHECK is added. From this
-- release dynamic registration refuses an `admin:` scope whatever the
-- allowlist says, so such an entry has no use left. Clients that already hold
-- one keep their scopes: this touches the realm's allowlist only.
UPDATE "realms"
SET
  "dynamic_registration_allowed_scopes" = (
    SELECT coalesce(jsonb_agg(entry."scope" ORDER BY entry."position"), '[]'::jsonb)
    FROM jsonb_array_elements("realms"."dynamic_registration_allowed_scopes")
      WITH ORDINALITY AS entry("scope", "position")
    WHERE NOT jsonb_path_exists(entry."scope", '$ ? (@ like_regex "^[aA][dD][mM][iI][nN]:")')
  ),
  "updated_at" = (EXTRACT(EPOCH FROM NOW())::bigint * 1000)
WHERE jsonb_typeof("dynamic_registration_allowed_scopes") = 'array'
  AND jsonb_path_exists("dynamic_registration_allowed_scopes", '$[*] ? (@ like_regex "^[aA][dD][mM][iI][nN]:")');
--> statement-breakpoint
ALTER TABLE "realms" ADD CONSTRAINT "realms_dynamic_registration_scopes_not_admin" CHECK (NOT jsonb_path_exists("realms"."dynamic_registration_allowed_scopes", '$[*] ? (@ like_regex "^[aA][dD][mM][iI][nN]:")'));
