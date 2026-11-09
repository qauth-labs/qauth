import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import { AUTH_METHOD_CONTRACT } from './contract.js';
import { AuthMethodContractError } from './errors.js';
import {
  defineUpstreamOidcPreset,
  isUpstreamOidcPreset,
  UPSTREAM_OIDC_PRESET_EXPORT,
  upstreamClaimIsTrue,
  type UpstreamOidcPresetOptions,
  upstreamOidcPresetProblems,
} from './upstream-oidc-preset.js';

const configSchema = z.strictObject({
  clientId: z.string().min(1),
  clientSecret: z.string().min(1).meta({ writeOnly: true }),
});
type Config = z.output<typeof configSchema>;

const OPTIONS: UpstreamOidcPresetOptions<Config> = {
  id: 'example-idp',
  type: 'example_idp',
  display: { name: 'Example IdP' },
  origins: ['https://idp.example.com'],
  configSchema,
  upstreamConfig: (config) => ({
    issuer: 'https://idp.example.com',
    clientId: config.clientId,
    clientAuthentication: { method: 'client_secret_basic', clientSecret: config.clientSecret },
  }),
};

function problemsOf(changes: Record<string, unknown>): string[] {
  return upstreamOidcPresetProblems({ ...OPTIONS, contract: AUTH_METHOD_CONTRACT, ...changes });
}

describe('defineUpstreamOidcPreset (#671)', () => {
  it('names the export a preset package uses', () => {
    expect(UPSTREAM_OIDC_PRESET_EXPORT).toBe('upstreamOidcPreset');
  });

  it('freezes the options with the contract they are written against', () => {
    const preset = defineUpstreamOidcPreset(OPTIONS);
    expect(preset.contract).toBe(AUTH_METHOD_CONTRACT);
    expect(preset.type).toBe('example_idp');
    expect(Object.isFrozen(preset)).toBe(true);
    expect(Object.isFrozen(preset.origins)).toBe(true);
    expect(isUpstreamOidcPreset(preset)).toBe(true);
  });

  it('copies the lists it keeps, so a later change to the caller’s array changes nothing', () => {
    const origins = ['https://idp.example.com'];
    const preset = defineUpstreamOidcPreset({ ...OPTIONS, origins });
    origins.push('https://other.example.com');
    expect(preset.origins).toEqual(['https://idp.example.com']);
  });

  it('refuses options with problems, listing each', () => {
    let error: unknown;
    try {
      defineUpstreamOidcPreset({ ...OPTIONS, id: 'oidc', origins: ['http://idp.example.com'] });
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(AuthMethodContractError);
    expect((error as AuthMethodContractError).problems).toEqual([
      "id oidc is the generic upstream OpenID Connect client's, which no preset may take",
      'origins[0] must be a bare https origin, such as https://idp.example.com',
    ]);
  });
});

describe('upstreamOidcPresetProblems (#671)', () => {
  it('finds none in a correct preset', () => {
    expect(problemsOf({})).toEqual([]);
  });

  it('refuses a value that is not an object', () => {
    expect(upstreamOidcPresetProblems(null)).toEqual(['it is not an object']);
  });

  it('refuses another contract version, or none', () => {
    expect(problemsOf({ contract: 'qauth-auth-method/0' })).toEqual([
      `it is written against the contract qauth-auth-method/0, and this server implements ${AUTH_METHOD_CONTRACT}`,
    ]);
    expect(problemsOf({ contract: undefined })).toEqual([
      `contract must be ${AUTH_METHOD_CONTRACT}`,
    ]);
  });

  it("refuses the generic client's id and type namespace, and a reserved type", () => {
    expect(problemsOf({ type: 'oidc_example' })).toEqual([
      "type oidc_example is in the generic upstream OpenID Connect client's namespace (oidc_<alias>), which no preset may take",
    ]);
    // The rest of the prefix claim resolution ranks as the generic client's.
    for (const type of ['oidc_', 'oidc__example']) {
      expect(problemsOf({ type })).toEqual([
        `type ${type} is in the generic upstream OpenID Connect client's namespace (oidc_<alias>), which no preset may take`,
      ]);
    }
    expect(problemsOf({ type: 'wallet' })).toEqual([
      "type wallet is reserved for QAuth's own credentials",
    ]);
    expect(problemsOf({ id: 'Example' })).toHaveLength(1);
  });

  it('refuses origins that are not one to eight distinct bare https origins', () => {
    expect(problemsOf({ origins: [] })).toHaveLength(1);
    expect(
      problemsOf({ origins: Array.from({ length: 9 }, (_, n) => `https://idp${n}.example.com`) })
    ).toHaveLength(1);
    expect(problemsOf({ origins: ['https://idp.example.com/path'] })).toEqual([
      'origins[0] must be a bare https origin, such as https://idp.example.com',
    ]);
    expect(problemsOf({ origins: ['https://idp.example.com', 'https://idp.example.com'] })).toEqual(
      ['origins must not repeat']
    );
  });

  it('refuses members of the wrong kind', () => {
    expect(
      problemsOf({ configSchema: {}, upstreamConfig: 'x', identityClaims: 1, display: {} })
    ).toEqual([
      expect.stringContaining('display.name must be'),
      'configSchema must be a Zod schema',
      'upstreamConfig must be a function of the parsed config',
      'identityClaims must be a function when the preset has it',
    ]);
  });

  it('refuses response members that are protocol parameters, badly named, too many or no function', () => {
    const map = (value: string) => value;
    expect(problemsOf({ responseMembers: { state: map } })).toEqual([
      'responseMembers names state, a parameter of the protocol, which the client reads itself',
    ]);
    expect(problemsOf({ responseMembers: { User: map } })).toHaveLength(1);
    expect(problemsOf({ responseMembers: { user: 'x' } })).toEqual([
      'responseMembers.user must be a function',
    ]);
    expect(problemsOf({ responseMembers: {} })).toEqual([
      'responseMembers must name one to 4 members',
    ]);
    expect(problemsOf({ responseMembers: { a: map, b: map, c: map, d: map, e: map } })).toEqual([
      'responseMembers must name one to 4 members',
    ]);
  });

  it('refuses attribute rules without a claim, with a bad key or a verified that is no function', () => {
    expect(problemsOf({ attributes: 'email' })).toEqual([
      'attributes must be a list of claim attribute rules',
    ]);
    expect(
      problemsOf({
        attributes: [{ claim: '' }, { claim: 'Name' }, { claim: 'email', verified: true }],
      })
    ).toEqual([
      'attributes[0].claim must name a claim',
      expect.stringContaining('attributes[0] must map to an attribute key'),
      expect.stringContaining('attributes[1] must map to an attribute key'),
      'attributes[2].verified must be a function when the rule has it',
    ]);
    expect(problemsOf({ attributes: [{ claim: 'Name', attribute: 'name' }] })).toEqual([]);
  });
});

describe('upstreamClaimIsTrue', () => {
  it('is true only for the boolean true of an own member', () => {
    expect(upstreamClaimIsTrue({ email_verified: true }, 'email_verified')).toBe(true);
    expect(upstreamClaimIsTrue({ email_verified: 'true' }, 'email_verified')).toBe(false);
    expect(upstreamClaimIsTrue(Object.create({ email_verified: true }), 'email_verified')).toBe(
      false
    );
  });
});
