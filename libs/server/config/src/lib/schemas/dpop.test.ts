import { describe, expect, it } from 'vitest';

import { dpopEnvSchema } from './dpop';

/** The DPoP switch (ADR-014 §3, ADR-017 phase F3, issues #479 and #480). */

/** The boot errors for `env`, as the operator reads them. */
function bootErrors(env: Record<string, string>): string[] {
  const result = dpopEnvSchema.safeParse(env);
  if (result.success) return [];
  return result.error.issues.map((issue) => `${issue.path.join('.')}: ${issue.message}`);
}

describe('dpopEnvSchema', () => {
  it('is off when unset or blank, and false is accepted', () => {
    expect(dpopEnvSchema.parse({}).DPOP_ENABLED).toBe(false);
    expect(dpopEnvSchema.parse({ DPOP_ENABLED: ' ' }).DPOP_ENABLED).toBe(false);
    expect(dpopEnvSchema.parse({ DPOP_ENABLED: 'false' }).DPOP_ENABLED).toBe(false);
  });

  it('turns on with true, now that the token endpoint binds tokens (#480)', () => {
    expect(dpopEnvSchema.parse({ DPOP_ENABLED: 'true' }).DPOP_ENABLED).toBe(true);
  });

  it('refuses a value that is not true or false', () => {
    expect(bootErrors({ DPOP_ENABLED: 'yes' })).toHaveLength(1);
    expect(bootErrors({ DPOP_ENABLED: 'TRUE' })).toHaveLength(1);
    expect(bootErrors({ DPOP_ENABLED: '1' })).toHaveLength(1);
  });
});
