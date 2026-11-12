import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import { AuthMethodContractError } from '../lib/errors.js';
import {
  defineUpstreamOidcPreset,
  MAX_UPSTREAM_RESPONSE_MEMBER_LENGTH,
  type UpstreamOidcPresetOptions,
} from '../lib/upstream-oidc-preset.js';
import { checkUpstreamOidcPreset } from './preset-kit.js';

/**
 * The preset kit (#671): it passes a correct preset, and for a wrong one it
 * names each problem it can find without the server.
 */

const configSchema = z.strictObject({
  clientId: z.string().min(1),
  clientSecret: z.string().min(1).meta({ writeOnly: true }),
  tenant: z
    .string()
    .regex(/^[a-z0-9-]{1,36}$/)
    .default('common'),
});
type Config = z.output<typeof configSchema>;

const OPTIONS: UpstreamOidcPresetOptions<Config> = {
  id: 'example-idp',
  type: 'example_idp',
  display: { name: 'Example IdP' },
  origins: ['https://idp.example.com'],
  configSchema,
  upstreamConfig: (config) => ({
    issuer: `https://idp.example.com/${config.tenant}/v2`,
    clientId: config.clientId,
    clientAuthentication: { method: 'client_secret_post', clientSecret: config.clientSecret },
    tenantIssuer: { template: 'https://idp.example.com/{tenantid}/v2', tenantClaim: 'tid' },
  }),
  responseMembers: {
    // Keeps the member's `name` and drops the rest: given its own output, it
    // gives the same back.
    user: (value) => {
      const parsed = JSON.parse(value) as { name?: unknown };
      return typeof parsed.name === 'string' ? JSON.stringify({ name: parsed.name }) : undefined;
    },
  },
  identityClaims: ({ response }) =>
    response['user'] === undefined
      ? {}
      : { name: (JSON.parse(response['user']) as { name: string }).name },
};

const SCENARIO = {
  configs: [{ clientId: 'kit-client', clientSecret: 'kit-secret-value-0123' }],
  response: { user: JSON.stringify({ name: 'Ada', email: 'ada@example.com' }) },
};

/** The problems the kit names for `options`, or `[]` when it passes. */
function kitProblems(
  options: Partial<UpstreamOidcPresetOptions<Config>>,
  scenario: Parameters<typeof checkUpstreamOidcPreset>[1] = SCENARIO
): readonly string[] {
  try {
    checkUpstreamOidcPreset(
      defineUpstreamOidcPreset({ ...OPTIONS, ...options } as UpstreamOidcPresetOptions<Config>),
      scenario
    );
    return [];
  } catch (error) {
    if (error instanceof AuthMethodContractError) return error.problems;
    throw error;
  }
}

describe('checkUpstreamOidcPreset (#671)', () => {
  it('passes a correct preset and says what it checked', () => {
    expect(checkUpstreamOidcPreset(defineUpstreamOidcPreset(OPTIONS), SCENARIO).checks).toEqual([
      'static',
      'config-schema',
      'upstream-config',
      'secret',
      'response-members',
      'identity-claims',
    ]);
  });

  it('runs the static checks first, on a value that is no preset', () => {
    expect(() => checkUpstreamOidcPreset({ ...OPTIONS }, SCENARIO)).toThrow(
      /contract must be qauth-auth-method/
    );
  });

  it('needs a config, and every config must pass the schema', () => {
    expect(kitProblems({}, { configs: [] })).toEqual([
      'the scenario must give at least one config',
    ]);
    expect(kitProblems({}, { configs: [{ clientId: 'kit-client' }] })).toEqual([
      'configs[0] does not pass configSchema at clientSecret',
    ]);
  });

  it('refuses a provider config off the origins, or a template without its placeholder in the path', () => {
    expect(
      kitProblems({
        upstreamConfig: (config) => ({
          issuer: 'https://other.example.com',
          clientId: config.clientId,
          clientAuthentication: { method: 'client_secret_post', clientSecret: config.clientSecret },
          endpoints: {
            authorization: 'https://idp.example.com/authorize',
            token: 'http://idp.example.com/token',
            jwks: 'https://other.example.com/jwks',
          },
          tenantIssuer: { template: 'https://{tenantid}.example.com/v2', tenantClaim: 'tid' },
        }),
      })
    ).toEqual([
      "configs[0]: issuer is off the preset's origins",
      'configs[0]: endpoints.token must be an https URL',
      "configs[0]: endpoints.jwks is off the preset's origins",
      "configs[0]: tenantIssuer.template is off the preset's origins",
      'configs[0]: tenantIssuer.template holds the tenant id outside its path',
    ]);
  });

  it('refuses an upstreamConfig that throws, or a client authentication a preset may not use', () => {
    expect(
      kitProblems({
        upstreamConfig: () => {
          throw new Error('no');
        },
      })
    ).toEqual(['upstreamConfig throws for configs[0]']);
    expect(
      kitProblems({
        upstreamConfig: (config) =>
          ({
            issuer: 'https://idp.example.com',
            clientId: config.clientId,
            clientAuthentication: { method: 'none' },
          }) as never,
      })
    ).toEqual([
      'configs[0]: clientAuthentication.method must be one of client_secret_basic, client_secret_post, private_key_jwt, signed_client_secret',
    ]);
  });

  it('refuses a client secret taken from a plain member, and a secret anywhere else', () => {
    expect(
      kitProblems({
        upstreamConfig: (config) => ({
          issuer: 'https://idp.example.com',
          clientId: config.clientId,
          clientAuthentication: { method: 'client_secret_post', clientSecret: config.clientId },
        }),
      })
    ).toEqual([
      'configs[0]: the client secret is not the value of a config member the schema marks writeOnly, so the server would store it in the clear',
    ]);
    expect(
      kitProblems({
        upstreamConfig: (config) => ({
          issuer: 'https://idp.example.com',
          clientId: config.clientId,
          clientAuthentication: { method: 'client_secret_post', clientSecret: config.clientSecret },
          scopes: ['openid', `x-${config.clientSecret}`],
        }),
      })
    ).toEqual([
      'configs[0]: the provider config carries the value of a writeOnly member at scopes.1, which would be sent in the clear',
    ]);
  });

  it('refuses a response member map that throws, makes too long a value or changes its own output', () => {
    expect(
      kitProblems({
        responseMembers: { user: () => 'x'.repeat(MAX_UPSTREAM_RESPONSE_MEMBER_LENGTH + 1) },
      })
    ).toEqual([
      'responseMembers.user makes a value longer than 1024 characters, which the bounce drops',
    ]);
    expect(kitProblems({ responseMembers: { user: (value) => `prefix:${value}` } })).toEqual([
      'responseMembers.user does not give its own output back unchanged: the callback maps the value the bounce carried again',
    ]);
    expect(
      kitProblems({
        responseMembers: {
          user: () => {
            throw new Error('no');
          },
        },
      })
    ).toEqual(["responseMembers.user throws for the scenario's value"]);
  });

  it('refuses identityClaims that set sub, a claim only the ID token carries or a vouched claim', () => {
    expect(
      kitProblems({
        identityClaims: () => ({
          sub: 'other',
          acr: 'high',
          email: 'made-up@example.com',
          email_verified: true,
          name: 'Ada',
          phone_number: undefined,
        }),
      })
    ).toEqual(
      ['sub', 'acr', 'email', 'email_verified'].map(
        (name) =>
          `identityClaims sets ${name}, which the client keeps as the provider's: a preset may remove a claim the provider vouches for, never set one, and sets neither sub nor a claim only the ID token carries`
      )
    );
  });
});
