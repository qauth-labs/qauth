import { describe, expect, it } from 'vitest';

import { readConfiguredEnv } from './configured-env';
import { experimentalSettingWarnings } from './experimental';
import { CONFIG_KEY_REGISTRY } from './keys';
import { type ConfigKeyInput, defineKeys } from './types';

/**
 * ADR-018 §5: the server logs a warning at boot for each experimental setting
 * that is on. An experimental key warns whenever it is set; a stable or
 * advanced key warns when it is set to one of its experimental values.
 */

const EXPERIMENTAL_KEY: ConfigKeyInput = {
  name: 'TRY_THIS',
  tier: 'experimental',
  role: 'deployment',
  owner: 'server',
  default: null,
  since: '0.2.0',
  docs: 'An experimental key for this test.',
};

const KEY_WITH_EXPERIMENTAL_VALUE: ConfigKeyInput = {
  name: 'MODE',
  tier: 'stable',
  role: 'deployment',
  owner: 'server',
  default: 'safe',
  since: '0.1.0',
  experimentalValues: ['bold'],
  docs: 'A stable key with an experimental value for this test.',
};

const REGISTRY = defineKeys([EXPERIMENTAL_KEY, KEY_WITH_EXPERIMENTAL_VALUE]);

describe('experimentalSettingWarnings', () => {
  it('warns for an experimental key that is set', () => {
    expect(experimentalSettingWarnings({ TRY_THIS: 'false' }, REGISTRY)).toEqual([
      {
        variable: 'TRY_THIS',
        message:
          'TRY_THIS is experimental. It may change in any release, without a deprecation window. ' +
          'See the configuration page.',
      },
    ]);
  });

  it('warns for a key set to an experimental value, naming the value', () => {
    expect(experimentalSettingWarnings({ MODE: 'bold' }, REGISTRY)).toEqual([
      {
        variable: 'MODE',
        message: expect.stringMatching(/^MODE=bold is experimental\./),
      },
    ]);
  });

  it('ignores whitespace around the value', () => {
    expect(experimentalSettingWarnings({ MODE: ' bold ' }, REGISTRY)).toHaveLength(1);
  });

  it.each([
    ['nothing is set', {}],
    ['the experimental key is blank', { TRY_THIS: '' }],
    ['the key has a stable value', { MODE: 'safe' }],
  ])('stays quiet when %s', (_label, env) => {
    expect(experimentalSettingWarnings(env, REGISTRY)).toEqual([]);
  });

  it('warns once per setting', () => {
    expect(
      experimentalSettingWarnings({ TRY_THIS: 'on', MODE: 'bold' }, REGISTRY).map(
        (warning) => warning.variable
      )
    ).toEqual(['TRY_THIS', 'MODE']);
  });

  it('never shows the value of a secret key', () => {
    const secrets = defineKeys([
      { ...EXPERIMENTAL_KEY, name: 'TRY_SECRET', secret: true },
      {
        ...KEY_WITH_EXPERIMENTAL_VALUE,
        name: 'SECRET_MODE',
        secret: true,
        default: { computed: 'a test value' },
        experimentalValues: ['hunter2-experimental'],
      },
    ]);

    const warnings = experimentalSettingWarnings(
      { TRY_SECRET: 'hunter2-secret-value', SECRET_MODE: 'hunter2-experimental' },
      secrets
    );

    expect(warnings).toHaveLength(2);
    expect(JSON.stringify(warnings)).not.toContain('hunter2');
  });

  it('warns for an experimental key set under an old name', () => {
    const renamed = defineKeys([
      { ...EXPERIMENTAL_KEY, aliases: [{ name: 'OLD_TRY_THIS', deprecatedSince: '0.2.0' }] },
    ]);

    expect(
      readConfiguredEnv(renamed, { OLD_TRY_THIS: 'true' }).experimental.map(
        (warning) => warning.variable
      )
    ).toEqual(['TRY_THIS']);
  });
});

describe('the real registry', () => {
  // ADR-018 §4: the base profile allows looser options than HAIP 1.0, such as
  // unsigned requests, so it stays outside the stability promise.
  it('warns for OID4VP_VERIFIER_PROFILE=oid4vp-1.0-base', () => {
    expect(
      experimentalSettingWarnings(
        { OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base' },
        CONFIG_KEY_REGISTRY
      )
    ).toEqual([
      {
        variable: 'OID4VP_VERIFIER_PROFILE',
        message: expect.stringMatching(/^OID4VP_VERIFIER_PROFILE=oid4vp-1\.0-base is experimental/),
      },
    ]);
  });

  it('does not warn for OID4VP_VERIFIER_PROFILE=haip-1.0', () => {
    expect(
      experimentalSettingWarnings({ OID4VP_VERIFIER_PROFILE: 'haip-1.0' }, CONFIG_KEY_REGISTRY)
    ).toEqual([]);
  });
});
