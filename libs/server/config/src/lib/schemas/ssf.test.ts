import { describe, expect, it } from 'vitest';

import { ssfEnvSchema } from './ssf';

/** The SSF transmitter's switch (issue #410). */

describe('ssfEnvSchema', () => {
  it('is off when unset or blank, and false is accepted', () => {
    expect(ssfEnvSchema.parse({}).SSF_TRANSMITTER_ENABLED).toBe(false);
    expect(ssfEnvSchema.parse({ SSF_TRANSMITTER_ENABLED: ' ' }).SSF_TRANSMITTER_ENABLED).toBe(
      false
    );
    expect(ssfEnvSchema.parse({ SSF_TRANSMITTER_ENABLED: 'false' }).SSF_TRANSMITTER_ENABLED).toBe(
      false
    );
  });

  it('turns on with true', () => {
    expect(ssfEnvSchema.parse({ SSF_TRANSMITTER_ENABLED: 'true' }).SSF_TRANSMITTER_ENABLED).toBe(
      true
    );
  });

  it('refuses a value that is not true or false', () => {
    for (const value of ['yes', 'TRUE', '1']) {
      expect(ssfEnvSchema.safeParse({ SSF_TRANSMITTER_ENABLED: value }).success).toBe(false);
    }
  });
});
