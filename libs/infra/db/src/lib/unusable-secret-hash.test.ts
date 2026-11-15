import { verify } from '@node-rs/argon2';
import { describe, expect, it } from 'vitest';

import { unusableSecretHash } from './unusable-secret-hash';

describe('unusableSecretHash (#1138)', () => {
  it('is an argon2id hash with the auth server parameters, new on every call', () => {
    const first = unusableSecretHash();
    expect(first).toMatch(
      /^\$argon2id\$v=19\$m=65536,t=3,p=4\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$/
    );
    expect(unusableSecretHash()).not.toBe(first);
  });

  it('verifies no secret', async () => {
    const stored = unusableSecretHash();
    for (const candidate of ['', 'secret', '0'.repeat(64)]) {
      expect(await verify(stored, candidate)).toBe(false);
    }
  });
});
