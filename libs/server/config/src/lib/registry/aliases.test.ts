import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import { applyKeyAliases, KeyAliasConflictError } from './aliases';
import { readConfiguredEnv } from './configured-env';
import { CONFIG_KEY_REGISTRY } from './keys';
import { type ConfigKeyInput, defineKeys } from './types';

/**
 * The one alias mechanism every renamed key goes through (ADR-018 §5). The
 * real alias, `REQUIRE_EMAIL_VERIFIED`, is pinned in `schemas/auth.test.ts`
 * and in the auth server's `env.test.ts`; these cases use made-up keys.
 */

function registry(...inputs: ConfigKeyInput[]) {
  return defineKeys(inputs);
}

const RENAMED: ConfigKeyInput = {
  name: 'NEW_NAME',
  tier: 'stable',
  role: 'deployment',
  owner: 'server',
  default: null,
  since: '0.1.0',
  aliases: [{ name: 'OLD_NAME', deprecatedSince: '0.2.0' }],
  docs: 'A renamed key for this test.',
};

const SECRET_RENAMED: ConfigKeyInput = {
  ...RENAMED,
  name: 'NEW_SECRET',
  secret: true,
  aliases: [{ name: 'OLD_SECRET', deprecatedSince: '0.2.0' }],
};

describe('applyKeyAliases', () => {
  it('uses the old name when only the old name is set, with one warning', () => {
    const result = applyKeyAliases({ OLD_NAME: 'value' }, registry(RENAMED));

    expect(result.env).toEqual({ NEW_NAME: 'value' });
    expect(result.deprecations).toEqual([
      {
        variable: 'OLD_NAME',
        replacement: 'NEW_NAME',
        message:
          'OLD_NAME is deprecated since 0.2.0. Rename it to NEW_NAME. ' +
          'The old name still works during the deprecation window.',
      },
    ]);
    expect(result.sources.get('NEW_NAME')).toBe('OLD_NAME');
  });

  it('uses the current name, and still warns, when both are set to the same value', () => {
    const result = applyKeyAliases({ NEW_NAME: 'same', OLD_NAME: 'same' }, registry(RENAMED));

    expect(result.env).toEqual({ NEW_NAME: 'same' });
    expect(result.deprecations).toHaveLength(1);
    expect(result.deprecations[0]?.message).toBe(
      'OLD_NAME is deprecated and duplicates NEW_NAME. Remove OLD_NAME.'
    );
    expect(result.sources.has('NEW_NAME')).toBe(false);
  });

  it('fails when both are set to different values, naming both', () => {
    const run = () => applyKeyAliases({ NEW_NAME: 'a', OLD_NAME: 'b' }, registry(RENAMED));

    expect(run).toThrow(KeyAliasConflictError);
    expect(run).toThrow('NEW_NAME=a and OLD_NAME=b disagree.');
    expect(run).toThrow('Remove it and keep only NEW_NAME.');
  });

  it('reports every conflict at once', () => {
    const other: ConfigKeyInput = {
      ...RENAMED,
      name: 'OTHER_NEW',
      aliases: [{ name: 'OTHER_OLD', deprecatedSince: '0.2.0' }],
    };

    try {
      applyKeyAliases(
        { NEW_NAME: 'a', OLD_NAME: 'b', OTHER_NEW: 'c', OTHER_OLD: 'd' },
        registry(RENAMED, other)
      );
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(KeyAliasConflictError);
      expect((error as KeyAliasConflictError).conflicts).toHaveLength(2);
    }
  });

  it.each([
    ['unset', {}],
    ['blank, as `${VAR:-}` in docker-compose.yml expands to', { OLD_NAME: '' }],
    ['whitespace', { OLD_NAME: '   ' }],
  ])('ignores an old name that is %s, without a warning', (_label, raw) => {
    const result = applyKeyAliases({ NEW_NAME: 'kept', ...raw }, registry(RENAMED));

    expect(result.env).toEqual({ NEW_NAME: 'kept' });
    expect(result.deprecations).toEqual([]);
  });

  it('treats a blank current name as unset, so the old name still counts', () => {
    const result = applyKeyAliases({ NEW_NAME: '', OLD_NAME: 'value' }, registry(RENAMED));

    expect(result.env).toEqual({ NEW_NAME: 'value' });
    expect(result.deprecations).toHaveLength(1);
  });

  it('removes the old name, so no schema can read it', () => {
    const result = applyKeyAliases({ OLD_NAME: '' }, registry(RENAMED));

    expect(result.env).not.toHaveProperty('OLD_NAME');
  });

  it('leaves every other variable alone and does not modify its input', () => {
    const raw = Object.freeze({ OLD_NAME: 'value', UNRELATED: 'x' });
    const result = applyKeyAliases(raw, registry(RENAMED));

    expect(result.env).toEqual({ NEW_NAME: 'value', UNRELATED: 'x' });
    expect(raw).toEqual({ OLD_NAME: 'value', UNRELATED: 'x' });
  });

  it('never shows the value of a secret key', () => {
    const SECRET = 'hunter2-secret-value';
    const OTHER = 'another-secret-value';

    const warned = applyKeyAliases({ OLD_SECRET: SECRET }, registry(SECRET_RENAMED));
    expect(JSON.stringify(warned.deprecations)).not.toContain(SECRET);

    const duplicated = applyKeyAliases(
      { NEW_SECRET: SECRET, OLD_SECRET: SECRET },
      registry(SECRET_RENAMED)
    );
    expect(JSON.stringify(duplicated.deprecations)).not.toContain(SECRET);

    const run = () =>
      applyKeyAliases({ NEW_SECRET: SECRET, OLD_SECRET: OTHER }, registry(SECRET_RENAMED));
    expect(run).toThrow('NEW_SECRET and OLD_SECRET are set to different values.');
    try {
      run();
    } catch (error) {
      expect(String(error)).not.toContain(SECRET);
      expect(String(error)).not.toContain(OTHER);
    }
  });

  it('applies the real registry: REQUIRE_EMAIL_VERIFIED is the old name of REQUIRE_VERIFIED_ACCOUNT', () => {
    const result = applyKeyAliases({ REQUIRE_EMAIL_VERIFIED: 'false' }, CONFIG_KEY_REGISTRY);

    expect(result.env).toEqual({ REQUIRE_VERIFIED_ACCOUNT: 'false' });
    expect(result.deprecations.map((warning) => warning.variable)).toEqual([
      'REQUIRE_EMAIL_VERIFIED',
    ]);
  });
});

describe('readConfiguredEnv', () => {
  const schema = z.object({ NEW_NAME: z.enum(['yes', 'no']).optional() });

  it('parses the aliased environment', () => {
    const configured = readConfiguredEnv(registry(RENAMED), { OLD_NAME: 'yes' });

    expect(configured.parse(schema)).toEqual({ NEW_NAME: 'yes' });
    expect(configured.deprecations).toHaveLength(1);
  });

  it('names the old name when a value read from it is invalid', () => {
    const configured = readConfiguredEnv(registry(RENAMED), { OLD_NAME: 'maybe' });

    expect(() => configured.parse(schema)).toThrow(z.ZodError);
    expect(() => configured.parse(schema)).toThrow(
      'the value comes from OLD_NAME, the deprecated name of NEW_NAME'
    );
  });

  it('leaves an issue on a key set under its current name as it is', () => {
    const configured = readConfiguredEnv(registry(RENAMED), { NEW_NAME: 'maybe' });

    expect(() => configured.parse(schema)).toThrow(/NEW_NAME/);
    expect(() => configured.parse(schema)).not.toThrow(/OLD_NAME/);
  });

  it('fails before any parse when an old and a current name disagree', () => {
    expect(() => readConfiguredEnv(registry(RENAMED), { NEW_NAME: 'yes', OLD_NAME: 'no' })).toThrow(
      KeyAliasConflictError
    );
  });
});
