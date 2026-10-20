import { describe, expect, it } from 'vitest';

import { kekEnvSchema } from './kek';

describe('kekEnvSchema', () => {
  it('selects the local provider when KEK_PROVIDER is unset or blank', () => {
    expect(kekEnvSchema.parse({}).KEK_PROVIDER).toBe('local');
    expect(kekEnvSchema.parse({ KEK_PROVIDER: '' }).KEK_PROVIDER).toBe('local');
    expect(kekEnvSchema.parse({ KEK_PROVIDER: '  ' }).KEK_PROVIDER).toBe('local');
  });

  it('keeps an adapter name as written, trimmed', () => {
    expect(kekEnvSchema.parse({ KEK_PROVIDER: ' vault ' }).KEK_PROVIDER).toBe('vault');
  });

  it('passes the KEK variables through for the key library to read', () => {
    const env = {
      KEK: 'a',
      KEK_PATH: '/run/secrets/kek',
      KEK_PREVIOUS: 'b',
      KEK_PREVIOUS_PATH: '/run/secrets/kek-previous',
    };

    expect(kekEnvSchema.parse(env)).toEqual({ KEK_PROVIDER: 'local', ...env });
  });

  it('leaves every KEK variable unset by default', () => {
    expect(kekEnvSchema.parse({})).toEqual({ KEK_PROVIDER: 'local' });
  });
});
