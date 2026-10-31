import { describe, expect, it } from 'vitest';

import { REALM_POLICY_REGISTRY } from './realm-policies';
import { realmSecretPaths } from './secret-store';
import { seedKeysSetIn } from './seed-keys';

/**
 * The seed keys an environment sets (#516): what the boot step names when a
 * realm that already has its policies ignores them, and the secret fields,
 * whose seeds go to the secret store instead.
 */
describe('seedKeysSetIn', () => {
  it('names each seed key set to a value, with the field it seeds, in registration order', () => {
    expect(
      seedKeysSetIn({
        PASSWORD_MIN_SCORE: '3',
        ACCESS_TOKEN_LIFESPAN: '600',
        PATH: '/usr/bin',
      })
    ).toEqual([
      { key: 'ACCESS_TOKEN_LIFESPAN', path: 'tokens.accessTokenLifespanSeconds' },
      { key: 'PASSWORD_MIN_SCORE', path: 'password.minScore' },
    ]);
  });

  it('counts a blank value as unset, as the server reads it', () => {
    expect(seedKeysSetIn({ PASSWORD_MIN_SCORE: '  ', ACCESS_TOKEN_LIFESPAN: '' })).toEqual([]);
    expect(seedKeysSetIn({ PASSWORD_MIN_SCORE: undefined })).toEqual([]);
  });

  it('counts an old key name under its current one', () => {
    expect(seedKeysSetIn({ REQUIRE_EMAIL_VERIFIED: 'false' })).toEqual([
      { key: 'REQUIRE_VERIFIED_ACCOUNT', path: 'accounts.requireVerifiedAccount' },
    ]);
  });

  it('leaves out the seed keys of secret fields, which seed the secret store', () => {
    expect(seedKeysSetIn({ SMTP_PASSWORD: 'secret', RESEND_API_KEY: 'key' })).toEqual([]);
  });

  it('can name every non-secret seed key of the registry', () => {
    const env: Record<string, string> = {};
    for (const { field } of REALM_POLICY_REGISTRY.fields()) {
      if (field.seedEnv !== null) env[field.seedEnv] = 'set';
    }
    const named = seedKeysSetIn(env).map(({ path }) => path);
    const seeded = REALM_POLICY_REGISTRY.fields()
      .filter(({ field }) => field.seedEnv !== null && !field.secret)
      .map(({ path }) => path);

    expect(named).toEqual(seeded);
  });
});

describe('realmSecretPaths', () => {
  it('lists the secret fields of the built-in groups', () => {
    expect(realmSecretPaths()).toEqual(['mail.smtp.password', 'mail.resend.apiKey']);
  });
});
