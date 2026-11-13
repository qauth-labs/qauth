import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import { upstreamAssertionClientOf, upstreamOidcPresetAssertionClient } from './assertion-client';

const ISSUER = 'https://idp.example.com';

describe('upstreamAssertionClientOf (#1073)', () => {
  it('names the client id, the algorithm and the assertion issuer of a signed client secret', () => {
    expect(
      upstreamAssertionClientOf({
        clientId: 'com.example.services',
        clientAuthentication: {
          method: 'signed_client_secret',
          signingAlgorithm: 'ES256',
          assertionIssuer: 'TEAM123456',
        },
      })
    ).toEqual({
      clientId: 'com.example.services',
      assertionIssuer: 'TEAM123456',
      algorithm: 'ES256',
    });
  });

  it('has no assertion issuer when the preset sets none, nor for private_key_jwt', () => {
    expect(
      upstreamAssertionClientOf({
        clientId: 'client',
        clientAuthentication: { method: 'signed_client_secret', signingAlgorithm: 'ES256' },
      })
    ).toEqual({ clientId: 'client', algorithm: 'ES256' });
    expect(
      upstreamAssertionClientOf({
        clientId: 'client',
        clientAuthentication: { method: 'private_key_jwt', signingAlgorithm: 'RS256' },
      })
    ).toEqual({ clientId: 'client', algorithm: 'RS256' });
  });

  it('is undefined for a client secret: the signer signs nothing for it', () => {
    expect(
      upstreamAssertionClientOf({
        clientId: 'client',
        clientAuthentication: { method: 'client_secret_basic' },
      })
    ).toBeUndefined();
  });
});

describe('upstreamOidcPresetAssertionClient (#1073)', () => {
  const schema = z.strictObject({ servicesId: z.string(), teamId: z.string().optional() });
  const preset = {
    type: 'example_idp',
    upstreamConfig: (config: z.output<typeof schema>) => ({
      issuer: ISSUER,
      clientId: config.servicesId,
      clientAuthentication: {
        method: 'signed_client_secret' as const,
        ...(config.teamId === undefined ? {} : { assertionIssuer: config.teamId }),
      },
    }),
  };

  it("reads the client id and the assertion issuer from the preset's provider config", () => {
    expect(
      upstreamOidcPresetAssertionClient(preset, {
        servicesId: 'com.example.services',
        teamId: 'TEAM123456',
      })
    ).toEqual({
      clientId: 'com.example.services',
      assertionIssuer: 'TEAM123456',
      algorithm: 'ES256',
    });
    expect(upstreamOidcPresetAssertionClient(preset, { servicesId: 'client' })).toEqual({
      clientId: 'client',
      algorithm: 'ES256',
    });
  });

  it('throws for a mapping that throws or makes a config that does not parse', () => {
    expect(() =>
      upstreamOidcPresetAssertionClient(
        {
          type: 'broken',
          upstreamConfig: () => {
            throw new Error('no');
          },
        },
        {}
      )
    ).toThrow(TypeError);
    expect(() =>
      upstreamOidcPresetAssertionClient(
        { type: 'broken', upstreamConfig: () => ({ issuer: ISSUER }) as never },
        {}
      )
    ).toThrow(TypeError);
  });
});
