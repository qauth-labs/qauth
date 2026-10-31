import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import * as config from '@qauth-labs/server-config';
import { isSecurityEffect } from '@qauth-labs/shared-validation';
import { describe, expect, it } from 'vitest';
import type { z } from 'zod';

import { ANNOTATION_KEYS, DIRECTION_KINDS, directionKind, SECURITY_WHEN } from './field';
import { renderRealmPoliciesPage } from './page';
import { REALM_POLICY_ENV, REALM_POLICY_REGISTRY } from './realm-policies';
import { PolicySeedError } from './registry';

/**
 * Contract tests over every registered group (#514): what each field must
 * carry, and how the schema agrees with the configuration key registry of
 * `@qauth-labs/server-config` (#449), whose `realm-seed` keys name the policy
 * path they seed.
 */

const REPO_ROOT = join(__dirname, '..', '..', '..', '..', '..');
const FIELDS = REALM_POLICY_REGISTRY.fields();

/**
 * The fields of #514's table, with the seed key, the direction and the rule.
 * A change here changes what needs `qauth:admin:security`, so the pull
 * request that makes it says why.
 *
 * These rows differ from the issue's table, each toward stricter:
 *
 * - the four token lifetimes are `loosening`, not `never`: the operation
 *   registry of #508 rules that lengthening a token lifetime is
 *   `posture-loosening` (`admin-operations-reserved.ts`, and the effect's
 *   description in `SECURITY_EFFECTS`);
 * - `mail.verificationTokenExpirySeconds` is `loosening` with
 *   `posture-loosening`, not `never`, by the same rule: the verification
 *   link's lifetime is a token lifetime (the maintainer's call on #890);
 * - `admin.twoAdminMandatoryOperations` is `any-change`, not `loosening`:
 *   ADR-019 Decision 7 lists "the two-admin configuration" among the changes
 *   of who administers, in either direction.
 */
const TABLE: Readonly<Record<string, readonly [string | null, string, string]>> = {
  'tokens.accessTokenLifespanSeconds': ['ACCESS_TOKEN_LIFESPAN', 'lower-is-stricter', 'loosening'],
  'tokens.developmentAccessTokenLifespanSeconds': [
    'DEV_ACCESS_TOKEN_LIFESPAN',
    'lower-is-stricter',
    'loosening',
  ],
  'tokens.refreshTokenLifespanSeconds': [
    'REFRESH_TOKEN_LIFESPAN',
    'lower-is-stricter',
    'loosening',
  ],
  'tokens.adminAccessTokenLifespanSeconds': [null, 'lower-is-stricter', 'loosening'],
  'accounts.requireVerifiedAccount': ['REQUIRE_VERIFIED_ACCOUNT', 'true-is-stricter', 'loosening'],
  'password.minScore': ['PASSWORD_MIN_SCORE', 'higher-is-stricter', 'loosening'],
  'bruteForce.enabled': ['FAILED_LOGIN_TRACKING_ENABLED', 'true-is-stricter', 'loosening'],
  'bruteForce.maxAttempts': ['FAILED_LOGIN_MAX_ATTEMPTS', 'lower-is-stricter', 'loosening'],
  'bruteForce.windowSeconds': ['FAILED_LOGIN_WINDOW', 'higher-is-stricter', 'loosening'],
  'bruteForce.lockoutSeconds': ['FAILED_LOGIN_LOCKOUT_DURATION', 'higher-is-stricter', 'loosening'],
  'registration.dynamicRegistrationAllowedScopes': [
    'DEFAULT_DYNAMIC_REGISTRATION_SCOPES',
    'subset-is-stricter',
    'loosening',
  ],
  'registration.cimd.enabled': ['CIMD_ENABLED', 'false-is-stricter', 'loosening'],
  'registration.cimd.trustPolicy': ['CIMD_TRUST_POLICY', 'ordered', 'loosening'],
  'registration.cimd.trustedDomains': ['CIMD_TRUSTED_DOMAINS', 'subset-is-stricter', 'loosening'],
  'mail.provider': ['EMAIL_PROVIDER', 'opaque', 'any-change'],
  'mail.fromAddress': ['EMAIL_FROM_ADDRESS', 'opaque', 'any-change'],
  'mail.fromName': ['EMAIL_FROM_NAME', 'opaque', 'any-change'],
  'mail.smtp.host': ['SMTP_HOST', 'opaque', 'any-change'],
  'mail.smtp.port': ['SMTP_PORT', 'opaque', 'any-change'],
  'mail.smtp.secure': ['SMTP_SECURE', 'opaque', 'any-change'],
  'mail.smtp.user': ['SMTP_USER', 'opaque', 'any-change'],
  'mail.smtp.password': ['SMTP_PASSWORD', 'opaque', 'any-change'],
  'mail.resend.apiKey': ['RESEND_API_KEY', 'opaque', 'any-change'],
  'mail.verificationTokenExpirySeconds': [
    'EMAIL_VERIFICATION_TOKEN_EXPIRY',
    'lower-is-stricter',
    'loosening',
  ],
  'mail.invalidateExistingTokensOnResend': [
    'EMAIL_VERIFICATION_INVALIDATE_EXISTING_ON_RESEND',
    'true-is-stricter',
    'never',
  ],
  'posture.maxEnvironmentLaxity': [null, 'ordered', 'loosening'],
  'admin.twoAdminMandatoryOperations': [null, 'superset-is-stricter', 'any-change'],
  'admin.workloadIssuers': [null, 'subset-is-stricter', 'any-change'],
};

/** The effect of each group's security changes (API-03's tags, as #514 assigns them). */
const GROUP_EFFECTS: Readonly<Record<string, readonly string[]>> = {
  tokens: ['posture-loosening'],
  accounts: ['credential-path'],
  password: ['credential-path'],
  bruteForce: ['credential-path'],
  registration: ['token-content'],
  mail: ['credential-path'],
  posture: ['posture-loosening'],
  admin: ['administration'],
};

/** The fields whose security changes carry another effect than their group's. */
const FIELD_EFFECTS: Readonly<Record<string, readonly string[]>> = {
  // A token lifetime, as the lifetimes of `tokens` are.
  'mail.verificationTokenExpirySeconds': ['posture-loosening'],
};

/** The fields CFG-14 leaves out of a sandbox promotion unless selected. */
const ENVIRONMENT_BOUND = (path: string) =>
  path.startsWith('mail.') ||
  [
    'registration.cimd.trustedDomains',
    'posture.maxEnvironmentLaxity',
    'admin.workloadIssuers',
  ].includes(path);

const SECRETS = ['mail.smtp.password', 'mail.resend.apiKey'];

/**
 * `realm-seed` keys whose policy no group of this schema has yet. Each is
 * added by the area that moves it to the realm row; the test fails when one
 * is modelled and still listed here, or when a new key is in neither place.
 */
const SEEDS_NOT_YET_IN_SCHEMA: Readonly<Record<string, string>> = {
  REDIRECT_URI_CUSTOM_SCHEMES: 'registration.redirectUriCustomSchemes',
  EVENT_RETENTION_USER_DAYS: 'retention.userEventDays',
  EVENT_RETENTION_ADMIN_DAYS: 'retention.adminEventDays',
};

describe('every field in every group', () => {
  // Acceptance criterion of #514.
  it('carries every annotation, each with a known value', () => {
    expect(FIELDS.length).toBeGreaterThan(0);
    for (const { path, field } of FIELDS) {
      for (const key of ANNOTATION_KEYS) {
        expect(Object.hasOwn(field, key), `${path} has ${key}`).toBe(true);
      }
      expect(DIRECTION_KINDS, path).toContain(directionKind(field.direction));
      expect(SECURITY_WHEN, path).toContain(field.securityWhen);
      expect(typeof field.secret, path).toBe('boolean');
      expect(typeof field.environmentBound, path).toBe('boolean');
      expect(field.doc.summary, path).toMatch(/^[A-Z].*\.$/);
      expect(field.doc.link, path).toMatch(/^https:\/\/docs\.qauth\.dev\//);
    }
  });

  // Acceptance criterion of #514.
  it('names an effect of the closed list when a change of it can be a security operation', () => {
    for (const { path, field } of FIELDS) {
      if (field.securityWhen === 'never') {
        expect(field.effects, path).toEqual([]);
      } else {
        expect(field.effects.length, path).toBeGreaterThan(0);
        for (const effect of field.effects)
          expect(isSecurityEffect(effect), `${path}: ${effect}`).toBe(true);
      }
    }
  });

  it('is the table of #514: seed key, direction and rule', () => {
    expect(
      Object.fromEntries(
        FIELDS.map(({ path, field }) => [
          path,
          [field.seedEnv, directionKind(field.direction), field.securityWhen],
        ])
      )
    ).toEqual(TABLE);
  });

  it('takes the effects of its group and the environment binding #514 assigns', () => {
    for (const { path, segments, field } of FIELDS) {
      if (field.securityWhen !== 'never')
        expect(field.effects, path).toEqual(FIELD_EFFECTS[path] ?? GROUP_EFFECTS[segments[0]]);
      expect(field.environmentBound, path).toBe(ENVIRONMENT_BOUND(path));
    }
  });

  it('links to a page of the docs site, and to a heading on it', () => {
    const generated = renderRealmPoliciesPage(REALM_POLICY_REGISTRY);
    for (const { path, field } of FIELDS) {
      const [, page, anchor] =
        /^https:\/\/docs\.qauth\.dev\/([^#]*?)\/?(?:#(.+))?$/.exec(field.doc.link) ?? [];
      const base = join(REPO_ROOT, 'apps/docs-site/src/content/docs', page ?? '');
      const file = [
        `${base}.md`,
        `${base}.mdx`,
        join(base, 'index.md'),
        join(base, 'index.mdx'),
      ].find(existsSync);
      expect(file, `${path}: ${field.doc.link}`).toBeDefined();
      if (anchor === undefined || file === undefined) continue;
      const body = page === 'reference/realm-policies' ? generated : readFileSync(file, 'utf8');
      const anchors = [...body.matchAll(/^#{2,6} (.+)$/gm)].map((match) =>
        match[1]
          .replace(/`/g, '')
          .toLowerCase()
          .replace(/[^a-z0-9 _-]/g, '')
          .replace(/ /g, '-')
      );
      expect(anchors, `${path}: #${anchor}`).toContain(anchor);
    }
  });
});

describe('every secret field', () => {
  // Acceptance criterion of #514.
  it('is write-only: set in the input, never in the document or the representation', () => {
    expect(FIELDS.filter(({ field }) => field.secret).map(({ path }) => path)).toEqual(SECRETS);
    const views = {
      input: REALM_POLICY_REGISTRY.toJsonSchema('input'),
      document: REALM_POLICY_REGISTRY.toJsonSchema('document'),
      representation: REALM_POLICY_REGISTRY.toJsonSchema('representation'),
    };
    const at = (schema: Record<string, unknown>, segments: readonly string[]) => {
      let node: Record<string, unknown> | undefined = schema;
      for (const segment of segments.slice(0, -1)) {
        node = (node?.['properties'] as Record<string, Record<string, unknown>> | undefined)?.[
          segment
        ];
      }
      return node?.['properties'] as Record<string, Record<string, unknown>>;
    };
    for (const { path, segments, field } of FIELDS) {
      const name = segments[segments.length - 1];
      if (!field.secret) {
        expect(at(views.input, segments)[name], path).not.toHaveProperty('writeOnly');
        continue;
      }
      expect(at(views.input, segments)[name], path).toMatchObject({ writeOnly: true });
      // A write may send the representation back, flag included.
      expect(at(views.input, segments)[`${name}Set`], path).toMatchObject({
        type: 'boolean',
        readOnly: true,
      });
      expect(at(views.document, segments), path).not.toHaveProperty(name);
      expect(at(views.representation, segments), path).not.toHaveProperty(name);
      expect(at(views.representation, segments)[`${name}Set`], path).toMatchObject({
        type: 'boolean',
        readOnly: true,
      });
      expect(Object.keys(at(views.document, segments)), path).not.toContain(`${name}Set`);
    }
  });

  it('never reaches the stored document, the representation or a diff', () => {
    const value = 'secret-value-for-the-contract-test';
    const input: Record<string, unknown> = {};
    for (const { segments, field } of FIELDS) {
      if (!field.secret) continue;
      let node = input;
      for (const segment of segments.slice(0, -1))
        node = (node[segment] ??= {}) as Record<string, unknown>;
      node[segments[segments.length - 1]] = value;
    }
    const parsed = REALM_POLICY_REGISTRY.parse(input, 'input');
    expect(() => REALM_POLICY_REGISTRY.parse(input, 'document')).toThrow();
    expect(JSON.stringify(REALM_POLICY_REGISTRY.toRepresentation(parsed, SECRETS))).not.toContain(
      value
    );
    expect(JSON.stringify(REALM_POLICY_REGISTRY.diffPolicies({}, input))).not.toContain(value);
    const seeded = REALM_POLICY_REGISTRY.defaultsFromEnv({
      SMTP_PASSWORD: value,
      RESEND_API_KEY: value,
    });
    expect(JSON.stringify(seeded)).not.toContain(value);
  });
});

describe('the configuration key registry (#449)', () => {
  const keys = new Map(config.CONFIG_KEY_REGISTRY.map((key) => [key.name, key]));

  /** Every key the env schemas of server-config read, with its field schema. */
  const envFields = new Map<string, z.ZodType>();
  for (const [name, schema] of Object.entries(config)) {
    if (!name.endsWith('EnvSchema')) continue;
    for (const [key, field] of Object.entries(config.envSchemaShape(schema as z.ZodType))) {
      envFields.set(key, field);
    }
  }

  it('lists each seed key as a realm-seed key of exactly that field, secret alike', () => {
    for (const { path, field } of FIELDS) {
      if (field.seedEnv === null) continue;
      const key = keys.get(field.seedEnv);
      expect(key, `${path}: ${field.seedEnv}`).toBeDefined();
      expect({ role: key?.role, seeds: key?.seeds, secret: key?.secret }, path).toEqual({
        role: 'realm-seed',
        seeds: path,
        secret: field.secret,
      });
    }
  });

  it('has a policy field for every realm-seed key of a registered group, or names it as not yet modelled', () => {
    const unmodelled: Record<string, string> = {};
    for (const key of config.CONFIG_KEY_REGISTRY) {
      if (key.role !== 'realm-seed' || key.seeds === undefined) continue;
      const field = REALM_POLICY_REGISTRY.field(key.seeds);
      if (field === undefined) unmodelled[key.name] = key.seeds;
      else expect(field.field.seedEnv, key.seeds).toBe(key.name);
    }
    expect(unmodelled).toEqual(SEEDS_NOT_YET_IN_SCHEMA);
  });

  it("gives each field its seed key's default, as the registry writes it", () => {
    for (const { path, field } of FIELDS) {
      if (field.seedEnv === null) continue;
      const { default: keyDefault } = keys.get(field.seedEnv) ?? {};
      if (typeof keyDefault === 'string') {
        const seeded = REALM_POLICY_REGISTRY.defaultsFromEnv({ [field.seedEnv]: keyDefault });
        let value: unknown = seeded;
        for (const segment of path.split('.')) value = (value as Record<string, unknown>)[segment];
        expect(value, `${path}: ${field.seedEnv}=${keyDefault}`).toEqual(field.default);
      } else {
        // No default, or required: the field has none either.
        expect(field.default, path).toBeNull();
      }
    }
  });

  it("reads every seed key with the server's own parser", () => {
    for (const { path, field } of FIELDS) {
      if (field.seedEnv === null) continue;
      expect(REALM_POLICY_ENV.parserOf(field.seedEnv), `${path}: ${field.seedEnv}`).toBe(
        envFields.get(field.seedEnv)
      );
    }
  });

  it("gives each field its env schema's default", () => {
    for (const { path, field } of FIELDS) {
      if (field.seedEnv === null) continue;
      const envField = envFields.get(field.seedEnv);
      expect(envField, `${field.seedEnv} is read by a server-config env schema`).toBeDefined();
      if (envField === undefined) continue;
      const unset = envField.safeParse(undefined);
      expect(unset.success ? (unset.data ?? null) : null, path).toEqual(field.default);
    }
  });

  /**
   * Raw values of each kind, as an operator writes them. Blank is in every
   * kind: Docker Compose passes an absent variable as `''`.
   */
  const BLANK = ['', ' '];
  const SAMPLES: Readonly<Record<string, readonly string[]>> = {
    number: [
      ...BLANK,
      '0',
      '1',
      '3',
      '60',
      '587',
      ' 900 ',
      '3600',
      '1e3',
      '0x10',
      '+5',
      '86400',
      '2.5',
      'soon',
    ],
    boolean: [...BLANK, 'true', 'false', '1', '0', 'TRUE', ' true ', 'yes'],
    list: [
      ...BLANK,
      'a',
      'openid profile',
      'openid,profile',
      ' x , y ',
      'openid openid',
      'Example.com',
      '*.example.org',
      'qauth:admin:read',
    ],
    text: [
      ...BLANK,
      'QAuth',
      'smtp',
      'resend',
      'mock',
      'allowlist',
      'accept-any-https',
      'noreply@example.com',
      'mail.example.com',
      'x',
    ],
  };
  const kindOf = (value: unknown, path: string) =>
    typeof value === 'number' || path.endsWith('.port')
      ? 'number'
      : typeof value === 'boolean'
        ? 'boolean'
        : Array.isArray(value)
          ? 'list'
          : 'text';
  const valueAtPath = (document: unknown, path: string) =>
    path
      .split('.')
      .reduce<unknown>((node, segment) => (node as Record<string, unknown>)[segment], document);

  // Every value the env schema accepts seeds the value it parses to (a set
  // without repeats); where seeding refuses one, the policy type refuses the
  // env schema's value too, so the refusal is the policy's stricter bound and
  // never a misreading of the string. A value the env schema refuses, which
  // stops the server, is refused too.
  it('reads a raw value as the env schema reads it', () => {
    let compared = 0;
    let refused = 0;
    for (const { path, field } of FIELDS) {
      if (field.seedEnv === null || field.secret) continue;
      const envField = envFields.get(field.seedEnv);
      if (envField === undefined) continue;
      for (const sample of SAMPLES[kindOf(field.default, path)]) {
        const parsed = envField.safeParse(sample);
        if (!parsed.success) {
          const key = field.seedEnv;
          expect(
            () => REALM_POLICY_REGISTRY.defaultsFromEnv({ [key]: sample }),
            `${key}=${JSON.stringify(sample)}`
          ).toThrow(PolicySeedError);
          refused++;
          continue;
        }
        // An optional key the env schema reads as unset seeds the default.
        const expected = Array.isArray(parsed.data)
          ? [...new Set(parsed.data as unknown[])]
          : parsed.data === undefined
            ? field.default
            : parsed.data;
        let seeded: unknown;
        try {
          seeded = valueAtPath(
            REALM_POLICY_REGISTRY.defaultsFromEnv({ [field.seedEnv]: sample }),
            path
          );
        } catch {
          expect(field.schema.safeParse(expected).success, `${field.seedEnv}=${sample}`).toBe(
            false
          );
          continue;
        }
        expect(seeded, `${field.seedEnv}=${JSON.stringify(sample)}`).toEqual(expected);
        compared++;
      }
    }
    expect(compared).toBeGreaterThan(40);
    expect(refused).toBeGreaterThan(20);
  });

  it('seeds from the parsed environment exactly what it seeds from the raw one', () => {
    for (const { path, field } of FIELDS) {
      if (field.seedEnv === null || field.secret) continue;
      const envField = envFields.get(field.seedEnv);
      if (envField === undefined) continue;
      for (const sample of SAMPLES[kindOf(field.default, path)]) {
        const parsed = envField.safeParse(sample);
        if (!parsed.success) continue;
        const seed = (value: unknown) => {
          try {
            return valueAtPath(
              REALM_POLICY_REGISTRY.defaultsFromEnv({ [field.seedEnv as string]: value }),
              path
            );
          } catch {
            return 'refused';
          }
        };
        expect(seed(parsed.data), `${field.seedEnv}=${JSON.stringify(sample)}`).toEqual(
          seed(sample)
        );
      }
    }
  });

  it('seeds through an old key name what it seeds through the current one', () => {
    let compared = 0;
    for (const key of config.CONFIG_KEY_REGISTRY) {
      if (key.role !== 'realm-seed' || key.seeds === undefined) continue;
      const entry = REALM_POLICY_REGISTRY.field(key.seeds);
      if (entry === undefined) continue;
      for (const alias of key.aliases) {
        for (const sample of SAMPLES[kindOf(entry.field.default, entry.path)]) {
          const seed = (name: string) => {
            try {
              return entry.field.secret
                ? REALM_POLICY_REGISTRY.secretSeedsFromEnv({ [name]: sample })
                : valueAtPath(
                    REALM_POLICY_REGISTRY.defaultsFromEnv({ [name]: sample }),
                    entry.path
                  );
            } catch (error) {
              return error instanceof Error ? error.name : 'refused';
            }
          };
          expect(seed(alias.name), `${alias.name}=${JSON.stringify(sample)}`).toEqual(
            seed(key.name)
          );
          compared++;
        }
      }
    }
    expect(compared).toBeGreaterThan(0);
  });
});
