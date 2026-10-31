-- The accounts the replays of the two password sign-in graphs start from (graphs/flows/core/sign-in-page and
-- graphs/flows/core/sign-in-token; their binding.yaml names each account). Replay fixture: never load it into a
-- database that serves real users.
--
-- Written as SQL on the host because the server has no API that makes a verified account without reading a mailbox
-- (POST /auth/verify needs the token the verification mail carries), and none that disables one. Each account is the
-- rows POST /auth/register and POST /auth/verify would leave: a users row, a password credential and the email
-- attribute, its verified flag mirroring the credential's email_verified.
--
-- Every password is the bindings' data.password, replay-sign-in-throwaway-2026. Its hash is Argon2id at the server's
-- default cost (m=65536, t=3, p=4), computed once with @node-rs/argon2; a hash records its own parameters, so the
-- server verifies it whatever cost it hashes new passwords with.
--
-- The accounts go into the realm named master, the default DEFAULT_REALM_NAME, which the server creates at its first
-- boot. Run it after that boot, with psql -v ON_ERROR_STOP=1. It may run again: rows that exist are left as they are.

BEGIN;

INSERT INTO users (id, realm_id, enabled)
SELECT a.id, r.id, a.enabled
FROM realms r
CROSS JOIN (
  VALUES
    ('0199fa20-5e1a-7000-8000-000000000001'::uuid, true), -- verified@sign-in.example
    ('0199fa20-5e1a-7000-8000-000000000002'::uuid, true), -- unverified@sign-in.example
    ('0199fa20-5e1a-7000-8000-000000000003'::uuid, false), -- disabled@sign-in.example
    ('0199fa20-5e1a-7000-8000-000000000004'::uuid, false), -- disabled-unverified@sign-in.example
    ('0199fa20-5e1a-7000-8000-000000000005'::uuid, true) -- lockout@sign-in.example
) AS a (id, enabled)
WHERE r.name = 'master'
ON CONFLICT (id) DO NOTHING;

INSERT INTO user_credentials (id, user_id, realm_id, provider_type, external_sub, credential_data)
SELECT a.id, a.user_id, r.id, 'password', a.email,
  jsonb_build_object(
    'password_hash', '$argon2id$v=19$m=65536,t=3,p=4$b/uZByz+llD+EJHaD4mzAw$oO14P12F5Ajc/KPHYG6KdOCPjkG3ss4XAcDFiXOE74E',
    'email_verified', a.email_verified
  )
FROM realms r
CROSS JOIN (
  VALUES
    ('0199fa20-5e1a-7000-8000-000000000101'::uuid, '0199fa20-5e1a-7000-8000-000000000001'::uuid,
      'verified@sign-in.example', true),
    ('0199fa20-5e1a-7000-8000-000000000102'::uuid, '0199fa20-5e1a-7000-8000-000000000002'::uuid,
      'unverified@sign-in.example', false),
    ('0199fa20-5e1a-7000-8000-000000000103'::uuid, '0199fa20-5e1a-7000-8000-000000000003'::uuid,
      'disabled@sign-in.example', true),
    ('0199fa20-5e1a-7000-8000-000000000104'::uuid, '0199fa20-5e1a-7000-8000-000000000004'::uuid,
      'disabled-unverified@sign-in.example', false),
    ('0199fa20-5e1a-7000-8000-000000000105'::uuid, '0199fa20-5e1a-7000-8000-000000000005'::uuid,
      'lockout@sign-in.example', true)
) AS a (id, user_id, email, email_verified)
WHERE r.name = 'master'
ON CONFLICT (id) DO NOTHING;

INSERT INTO user_attributes (user_id, source, attr_key, attr_value, verified)
SELECT c.user_id, 'self_reported', 'email', c.external_sub, (c.credential_data ->> 'email_verified')::boolean
FROM user_credentials c
WHERE c.id BETWEEN '0199fa20-5e1a-7000-8000-000000000101' AND '0199fa20-5e1a-7000-8000-000000000105'
ON CONFLICT (user_id, source, attr_key) DO NOTHING;

-- Fail, and roll everything back, when the realm is missing or another row holds one of these addresses.
DO $$
BEGIN
  IF (
    SELECT count(*)
    FROM user_credentials c
    JOIN realms r ON r.id = c.realm_id AND r.name = 'master'
    WHERE c.id BETWEEN '0199fa20-5e1a-7000-8000-000000000101' AND '0199fa20-5e1a-7000-8000-000000000105'
  ) <> 5 THEN
    RAISE EXCEPTION 'graphs/fixtures/users.sql: the realm master is missing, or one of its addresses is taken';
  END IF;
END
$$;

COMMIT;
