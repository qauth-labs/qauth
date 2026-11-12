import { AUTH_METHOD_TYPE_PATTERN } from '../lib/contract.js';
import { AuthMethodContractError } from '../lib/errors.js';
import {
  MAX_UPSTREAM_ASSERTION_ISSUER_LENGTH,
  MAX_UPSTREAM_RESPONSE_MEMBER_LENGTH,
  UPSTREAM_ID_TOKEN_ONLY_CLAIMS,
  UPSTREAM_PRESET_CLIENT_AUTHENTICATION_METHODS,
  UPSTREAM_SIGNED_CLIENT_SECRET,
  UPSTREAM_TENANT_PLACEHOLDER,
  UPSTREAM_VERIFIED_CLAIM_PAIRS,
  type UpstreamOidcPreset,
  upstreamOidcPresetProblems,
} from '../lib/upstream-oidc-preset.js';
import { configWriteOnlyValues } from './contract-kit.js';

/**
 * The preset kit (#671): what a preset's author calls, in any test runner, to
 * check an upstream OpenID Connect preset ({@link UpstreamOidcPreset}) without
 * the server. It checks what it can without the server's client:
 *
 * 1. the static checks the server's loader runs (`upstreamOidcPresetProblems`):
 *    the contract version, the id and type, the display data, the origins,
 *    the members' shapes;
 * 2. the config schema: each sample config parses, and the schema renders as
 *    a JSON Schema object;
 * 3. `upstreamConfig` on each sample config: it does not throw, its issuer,
 *    issuer template and endpoints are `https` URLs on the preset's origins,
 *    the template holds its placeholder once, in its path, and the client
 *    authentication is one the preset may use;
 * 4. the secret: a client secret is the value of a config member the schema
 *    marks `writeOnly`, and no such value is anywhere else in the provider
 *    config, where it would be sent and logged in the clear;
 * 5. the response members: each map takes the scenario's value without
 *    throwing, makes a value of at most 1024 characters or none, and gives
 *    its own output back unchanged, as the callback maps the value the bounce
 *    carried again;
 * 6. `identityClaims`: it sets no reserved claim, neither `sub`, nor a claim
 *    only the ID token carries, nor a claim the provider vouches for or its
 *    `*_verified` flag (a preset may remove those, never set one).
 *
 * The full sign-in, against the provider, is the plugin's end-to-end test
 * against the server.
 *
 * ```ts
 * import { checkUpstreamOidcPreset } from '@qauth-labs/plugin-sdk/testing';
 *
 * it('is a preset the server builds', () => {
 *   checkUpstreamOidcPreset(upstreamOidcPreset, {
 *     configs: [{ clientId: 'kit', clientSecret: 'kit-secret-value' }],
 *   });
 * });
 * ```
 *
 * EXPERIMENTAL, like the contract.
 *
 * @experimental
 */

/**
 * What {@link checkUpstreamOidcPreset} runs a preset on.
 *
 * @experimental
 */
export interface UpstreamOidcPresetKitScenario {
  /**
   * Configs as a realm's admin writes them: at least one. Give each secret a
   * realistic value (a dozen characters or more), so a short one does not
   * match another value by accident.
   */
  readonly configs: readonly unknown[];
  /**
   * The provider's claims `identityClaims` is handed; a sample with `sub`,
   * `iss`, `aud`, `email` and `email_verified` unless set.
   */
  readonly claims?: Readonly<Record<string, unknown>>;
  /**
   * The response members as the provider sends them, by name: each is put
   * through its map. A member the preset reads and this leaves out is not
   * checked.
   */
  readonly response?: Readonly<Record<string, string>>;
}

/**
 * What a passing run checked, in order.
 *
 * @experimental
 */
export interface UpstreamOidcPresetKitReport {
  readonly checks: readonly string[];
}

/** The claims `identityClaims` is handed unless the scenario sets its own. */
const SAMPLE_CLAIMS: Readonly<Record<string, unknown>> = Object.freeze({
  iss: 'https://idp.kit.invalid',
  sub: 'kit-subject',
  aud: 'kit-client',
  email: 'person@kit.invalid',
  email_verified: true,
});

/** Every claim a preset may not set: `sub`, the ID token's own and the vouched ones. */
const UNSETTABLE_CLAIMS: ReadonlySet<string> = new Set([
  'sub',
  ...UPSTREAM_ID_TOKEN_ONLY_CLAIMS,
  ...UPSTREAM_VERIFIED_CLAIM_PAIRS.flat(),
]);

/**
 * Check `preset` as the server's loader and client would take it.
 *
 * @throws AuthMethodContractError listing every failed check
 * @experimental
 */
export function checkUpstreamOidcPreset(
  preset: unknown,
  scenario: UpstreamOidcPresetKitScenario
): UpstreamOidcPresetKitReport {
  const subject = describeSubject(preset);
  const staticProblems = upstreamOidcPresetProblems(preset);
  if (staticProblems.length > 0) throw new AuthMethodContractError(subject, staticProblems);
  const checked = preset as UpstreamOidcPreset;
  const checks = ['static'];
  const problems: string[] = [];

  if (!Array.isArray(scenario.configs) || scenario.configs.length === 0) {
    throw new AuthMethodContractError(subject, ['the scenario must give at least one config']);
  }
  const parsed: unknown[] = [];
  scenario.configs.forEach((config, index) => {
    const result = checked.configSchema.safeParse(config);
    if (result.success) {
      parsed.push(result.data);
      return;
    }
    problems.push(
      `configs[${index}] does not pass configSchema at ${result.error.issues
        .map((issue) => issue.path.join('.') || '(root)')
        .join(', ')}`
    );
  });
  const firstSecrets = configWriteOnlyValues(checked.configSchema, parsed[0]);
  if (firstSecrets === undefined) problems.push('configSchema does not render as JSON Schema');
  if (problems.length > 0) throw new AuthMethodContractError(subject, problems);
  checks.push('config-schema');

  const origins = new Set(checked.origins);
  parsed.forEach((config, index) => {
    const at = `configs[${index}]`;
    let provider: unknown;
    try {
      provider = checked.upstreamConfig(config);
    } catch {
      problems.push(`upstreamConfig throws for ${at}`);
      return;
    }
    problems.push(
      ...providerConfigProblems(provider, origins).map((problem) => `${at}: ${problem}`)
    );
    const secrets = (configWriteOnlyValues(checked.configSchema, config) ?? []).filter(
      (value) => value.length > 0
    );
    problems.push(...secretProblems(provider, secrets).map((problem) => `${at}: ${problem}`));
  });
  checks.push('upstream-config', 'secret');

  const response: Record<string, string> = {};
  for (const [name, map] of Object.entries(checked.responseMembers ?? {})) {
    if (scenario.response === undefined || !Object.hasOwn(scenario.response, name)) continue;
    let value: string | undefined;
    try {
      value = map(scenario.response[name]);
    } catch {
      problems.push(`responseMembers.${name} throws for the scenario's value`);
      continue;
    }
    if (value === undefined) continue;
    if (typeof value !== 'string' || value.length === 0) {
      problems.push(`responseMembers.${name} must make a string or undefined`);
      continue;
    }
    if (value.length > MAX_UPSTREAM_RESPONSE_MEMBER_LENGTH) {
      problems.push(
        `responseMembers.${name} makes a value longer than ${MAX_UPSTREAM_RESPONSE_MEMBER_LENGTH} characters, which the bounce drops`
      );
      continue;
    }
    let again: string | undefined;
    try {
      again = map(value);
    } catch {
      again = undefined;
    }
    if (again !== value) {
      problems.push(
        `responseMembers.${name} does not give its own output back unchanged: the callback maps the value the bounce carried again`
      );
      continue;
    }
    response[name] = value;
  }
  checks.push('response-members');

  if (checked.identityClaims !== undefined) {
    const claims = scenario.claims ?? SAMPLE_CLAIMS;
    parsed.forEach((config, index) => {
      let made: unknown;
      try {
        made = checked.identityClaims?.({ claims, response, config });
      } catch {
        problems.push(`identityClaims throws for configs[${index}]`);
        return;
      }
      if (typeof made !== 'object' || made === null || Array.isArray(made)) {
        problems.push(`identityClaims must return an object of claims for configs[${index}]`);
        return;
      }
      for (const [name, value] of Object.entries(made)) {
        if (value !== undefined && UNSETTABLE_CLAIMS.has(name)) {
          problems.push(
            `identityClaims sets ${name}, which the client keeps as the provider's: a preset may remove a claim the provider vouches for, never set one, and sets neither sub nor a claim only the ID token carries`
          );
        }
      }
    });
  }
  checks.push('identity-claims');

  if (problems.length > 0) throw new AuthMethodContractError(subject, problems);
  return Object.freeze({ checks: Object.freeze(checks) });
}

/** The problems of a provider config's URLs and client authentication. */
function providerConfigProblems(provider: unknown, origins: ReadonlySet<string>): string[] {
  if (typeof provider !== 'object' || provider === null) {
    return ['upstreamConfig must return a provider config object'];
  }
  const config = provider as Record<string, unknown>;
  const problems: string[] = [];
  const onOrigins = (name: string, value: unknown) => {
    const origin = httpsOrigin(value);
    if (origin === undefined) problems.push(`${name} must be an https URL`);
    else if (!origins.has(origin)) problems.push(`${name} is off the preset's origins`);
  };
  onOrigins('issuer', config['issuer']);
  if (typeof config['clientId'] !== 'string' || config['clientId'].length === 0) {
    problems.push('clientId must be a string');
  }
  const authentication = config['clientAuthentication'];
  const method =
    typeof authentication === 'object' && authentication !== null
      ? (authentication as Record<string, unknown>)['method']
      : undefined;
  if (!(UPSTREAM_PRESET_CLIENT_AUTHENTICATION_METHODS as readonly unknown[]).includes(method)) {
    problems.push(
      `clientAuthentication.method must be one of ${UPSTREAM_PRESET_CLIENT_AUTHENTICATION_METHODS.join(', ')}`
    );
  }
  const assertionIssuer =
    typeof authentication === 'object' && authentication !== null
      ? (authentication as Record<string, unknown>)['assertionIssuer']
      : undefined;
  if (assertionIssuer !== undefined) {
    if (method !== UPSTREAM_SIGNED_CLIENT_SECRET) {
      problems.push(
        `clientAuthentication.assertionIssuer is taken only with ${UPSTREAM_SIGNED_CLIENT_SECRET}`
      );
    } else if (
      typeof assertionIssuer !== 'string' ||
      assertionIssuer.length === 0 ||
      assertionIssuer.length > MAX_UPSTREAM_ASSERTION_ISSUER_LENGTH ||
      // eslint-disable-next-line no-control-regex -- refusing control characters is the point
      /[\u0000-\u001f\u007f]/u.test(assertionIssuer)
    ) {
      problems.push(
        `clientAuthentication.assertionIssuer must be a string of 1 to ${MAX_UPSTREAM_ASSERTION_ISSUER_LENGTH} characters, no control character`
      );
    }
  }
  const endpoints = config['endpoints'];
  if (endpoints !== undefined) {
    if (typeof endpoints !== 'object' || endpoints === null) {
      problems.push('endpoints must be an object');
    } else {
      for (const [name, value] of Object.entries(endpoints)) {
        if (name !== 'issParameterSupported') onOrigins(`endpoints.${name}`, value);
      }
    }
  }
  const tenantIssuer = config['tenantIssuer'];
  if (tenantIssuer !== undefined) {
    const template =
      typeof tenantIssuer === 'object' && tenantIssuer !== null
        ? (tenantIssuer as Record<string, unknown>)['template']
        : undefined;
    if (typeof template !== 'string' || template.split(UPSTREAM_TENANT_PLACEHOLDER).length !== 2) {
      problems.push(`tenantIssuer.template must hold ${UPSTREAM_TENANT_PLACEHOLDER} once`);
    } else {
      const sample = template.replace(UPSTREAM_TENANT_PLACEHOLDER, 'tenant');
      const origin = httpsOrigin(sample);
      onOrigins('tenantIssuer.template', sample);
      if (origin !== undefined && template.indexOf(UPSTREAM_TENANT_PLACEHOLDER) <= origin.length) {
        problems.push('tenantIssuer.template holds the tenant id outside its path');
      }
    }
  }
  return problems;
}

/**
 * The problems of the provider config's secret: a client secret that is not
 * a `writeOnly` member's value, or a `writeOnly` value anywhere else.
 */
function secretProblems(provider: unknown, secrets: readonly string[]): string[] {
  if (typeof provider !== 'object' || provider === null) return [];
  const config = provider as Record<string, unknown>;
  const authentication = config['clientAuthentication'];
  const clientSecret =
    typeof authentication === 'object' && authentication !== null
      ? (authentication as Record<string, unknown>)['clientSecret']
      : undefined;
  const problems: string[] = [];
  if (clientSecret !== undefined && !secrets.includes(clientSecret as string)) {
    problems.push(
      'the client secret is not the value of a config member the schema marks writeOnly, so the server would store it in the clear'
    );
  }
  for (const [path, value] of stringsOf(config, [])) {
    if (path === 'clientAuthentication.clientSecret') continue;
    if (secrets.some((secret) => value.includes(secret))) {
      problems.push(
        `the provider config carries the value of a writeOnly member at ${path}, which would be sent in the clear`
      );
    }
  }
  return problems;
}

/** Every string of `value`, with its path. */
function stringsOf(value: unknown, path: readonly string[]): [path: string, value: string][] {
  if (typeof value === 'string') return [[path.join('.'), value]];
  if (typeof value !== 'object' || value === null || path.length > 8) return [];
  return Object.entries(value).flatMap(([key, member]) => stringsOf(member, [...path, key]));
}

/** The origin of an `https` URL, or `undefined`. */
function httpsOrigin(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' ? url.origin : undefined;
  } catch {
    return undefined;
  }
}

/** How the kit names a preset in its error. */
function describeSubject(value: unknown): string {
  const type =
    typeof value === 'object' && value !== null
      ? (value as Record<string, unknown>)['type']
      : undefined;
  return typeof type === 'string' && AUTH_METHOD_TYPE_PATTERN.test(type)
    ? `The upstream OpenID Connect preset ${type}`
    : 'An upstream OpenID Connect preset';
}
