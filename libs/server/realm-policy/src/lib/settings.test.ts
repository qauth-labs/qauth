import { join, resolve } from 'node:path';

import { REALM_POLICY_SETTINGS } from '@qauth-labs/shared-admin-settings';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import { ordered, PolicyDefinitionError, type PolicyField, policyField } from './field';
import { REALM_POLICY_REGISTRY } from './realm-policies';
import { createPolicyRegistry, type RegisteredPolicyField } from './registry';
import {
  REALM_POLICY_SETTINGS_PATH,
  realmPolicySettings,
  realmPolicySettingsText,
} from './settings';

/**
 * The settings metadata the admin console imports (#589): generated from the
 * schema, and refused for a field that has no explanation, docs link or
 * default.
 */

/** The repository root, five levels up from this file. */
const REPO_ROOT = resolve(__dirname, '..', '..', '..', '..', '..');

const LINK = 'https://docs.qauth.dev/reference/realm-policies/#test';

const minutes = policyField(z.int().min(1), {
  seedEnv: null,
  default: 15,
  direction: 'lower-is-stricter',
  securityWhen: 'loosening',
  effects: ['posture-loosening'],
  secret: false,
  environmentBound: false,
  doc: { summary: 'How long a test lasts, in minutes.', link: LINK },
});

/** A registry of one field, as `realmPolicySettings` reads it, past `policyField`'s checks. */
function registryOf(field: Record<string, unknown>) {
  const entry = { path: 'test.minutes', segments: ['test', 'minutes'], field } as unknown;
  return { version: '1-rc.0', fields: () => [entry as RegisteredPolicyField] };
}

describe('the settings metadata file (#589)', () => {
  // This test is the generator: when the schema changes,
  // `pnpm nx test server-realm-policy -- -u` rewrites the file, and without
  // `-u` the test fails until the committed file matches.
  it('is what the schema generates (regenerate with `pnpm nx test server-realm-policy -- -u`)', async () => {
    await expect(realmPolicySettingsText(REALM_POLICY_REGISTRY)).toMatchFileSnapshot(
      join(REPO_ROOT, REALM_POLICY_SETTINGS_PATH)
    );
  });

  it('is what @qauth-labs/shared-admin-settings exports', () => {
    expect(REALM_POLICY_SETTINGS).toEqual(realmPolicySettings(REALM_POLICY_REGISTRY));
  });

  it('describes every field of the schema, in its order, with its explanation, link and default', () => {
    const { settings, policySchemaVersion } = realmPolicySettings(REALM_POLICY_REGISTRY);
    expect(policySchemaVersion).toBe(REALM_POLICY_REGISTRY.version);
    expect(settings.map((setting) => setting.path)).toEqual(
      REALM_POLICY_REGISTRY.fields().map((entry) => entry.path)
    );
    for (const [index, { field }] of REALM_POLICY_REGISTRY.fields().entries()) {
      expect(settings[index]).toMatchObject({
        summary: field.doc.summary,
        docs: field.doc.link,
        default: field.secret ? null : field.default,
        secret: field.secret,
        securityWhen: field.securityWhen,
        effects: [...field.effects],
        environmentBound: field.environmentBound,
      });
    }
  });

  it('says what a change in each direction needs, as the diff classifies it', () => {
    const registry = createPolicyRegistry();
    registry.registerPolicyGroup('test', {
      minutes,
      level: policyField(z.enum(['low', 'high']), {
        seedEnv: null,
        default: 'high',
        direction: ordered(['low', 'high']),
        securityWhen: 'any-change',
        effects: ['credential-path'],
        secret: false,
        environmentBound: true,
        doc: { summary: 'How strict a test is.', link: LINK },
      }),
      label: policyField(z.string(), {
        seedEnv: null,
        default: 'a',
        direction: 'opaque',
        securityWhen: 'never',
        effects: [],
        secret: false,
        environmentBound: false,
        doc: { summary: 'What a test is called.', link: LINK },
      }),
      token: policyField(z.string(), {
        seedEnv: null,
        default: null,
        direction: 'opaque',
        securityWhen: 'any-change',
        effects: ['credential-path'],
        secret: true,
        environmentBound: false,
        doc: { summary: 'The token a test sends.', link: LINK },
      }),
    });
    const { settings } = realmPolicySettings(registry);
    expect(settings).toEqual([
      {
        path: 'test.minutes',
        summary: 'How long a test lasts, in minutes.',
        docs: LINK,
        default: 15,
        secret: false,
        direction: 'lower-is-stricter',
        securityWhen: 'loosening',
        class: { tightening: 'write', loosening: 'security', neutral: 'security' },
        effects: ['posture-loosening'],
        environmentBound: false,
      },
      {
        path: 'test.level',
        summary: 'How strict a test is.',
        docs: LINK,
        default: 'high',
        secret: false,
        direction: 'ordered',
        order: ['low', 'high'],
        securityWhen: 'any-change',
        class: { tightening: 'security', loosening: 'security', neutral: 'security' },
        effects: ['credential-path'],
        environmentBound: true,
      },
      {
        path: 'test.label',
        summary: 'What a test is called.',
        docs: LINK,
        default: 'a',
        secret: false,
        direction: 'opaque',
        securityWhen: 'never',
        class: { tightening: 'write', loosening: 'write', neutral: 'write' },
        effects: [],
        environmentBound: false,
      },
      {
        path: 'test.token',
        summary: 'The token a test sends.',
        docs: LINK,
        default: null,
        secret: true,
        direction: 'opaque',
        securityWhen: 'any-change',
        class: { tightening: 'security', loosening: 'security', neutral: 'security' },
        effects: ['credential-path'],
        environmentBound: false,
      },
    ]);
  });

  // Acceptance criterion of #589: a field without an explanation or a default
  // fails the metadata build. `policyField` refuses such a definition, so the
  // fields here are built past it, as another copy of the library could.
  it('fails for a field without an explanation, a docs link or a default', () => {
    const valid = { ...(minutes as PolicyField) } as Record<string, unknown>;
    expect(() => realmPolicySettings(registryOf(valid))).not.toThrow();

    const { default: _default, ...withoutDefault } = valid;
    for (const [field, message] of [
      [{ ...valid, doc: { summary: '', link: LINK } }, 'test.minutes has no one-sentence'],
      [{ ...valid, doc: { link: LINK } }, 'test.minutes has no one-sentence'],
      [
        { ...valid, doc: { summary: 'Two sentences. Here.', link: LINK } },
        'test.minutes has no one-sentence',
      ],
      [{ ...valid, doc: null }, 'test.minutes has no one-sentence'],
      [
        { ...valid, doc: { summary: 'How long a test lasts.', link: 'https://example.com/' } },
        'test.minutes has no https://docs.qauth.dev/ link',
      ],
      [withoutDefault, 'test.minutes has no default'],
      [{ ...valid, default: undefined }, 'test.minutes has no default'],
    ] as const) {
      const build = () => realmPolicySettings(registryOf(field));
      expect(build).toThrow(PolicyDefinitionError);
      expect(build).toThrow(message);
    }
  });
});
