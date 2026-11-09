import type {
  UpstreamOidcPresetOptions as SdkPresetOptions,
  UpstreamOidcProviderConfig,
} from '@qauth-labs/plugin-sdk';
import { describe, expect, it } from 'vitest';

import type { UpstreamOidcClientConfigInput } from './config';
import { upstreamOidcClientConfigSchema } from './config';
import type { UpstreamOidcPresetOptions } from './upstream-oidc-preset';

/**
 * ONE SHAPE (#671). A preset is written in its own repository against the
 * plugin SDK alone, and its `upstreamConfig` returns the SDK's
 * `UpstreamOidcProviderConfig`. This library parses that value with its own
 * Zod schema, `upstreamOidcClientConfigSchema`. The two must describe the
 * same config: a member the SDK offers and the schema refuses would fail
 * every sign-in of a preset that uses it, and a member the schema takes and
 * the SDK lacks could not be written by a preset at all.
 *
 * Checked by the typecheck, which covers this file: `Same` resolves to
 * `true` only when each type is assignable to the other.
 */

type Same<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false;

const providerConfigIsOneShape: Same<UpstreamOidcProviderConfig, UpstreamOidcClientConfigInput> =
  true;
const presetOptionsAreTheSdks: Same<
  UpstreamOidcPresetOptions<unknown>,
  SdkPresetOptions<unknown>
> = true;

describe("the preset's provider config is the plugin SDK's shape (#671)", () => {
  it('is the same type in the SDK and in the schema this library parses it with', () => {
    expect(providerConfigIsOneShape).toBe(true);
    expect(presetOptionsAreTheSdks).toBe(true);
  });

  it('parses a config written as the SDK types it, with every member the SDK offers', () => {
    const config: UpstreamOidcProviderConfig = {
      issuer: 'https://idp.example.com/tenant/v2',
      clientId: 'client',
      clientAuthentication: { method: 'signed_client_secret', signingAlgorithm: 'ES256' },
      scopes: ['openid', 'email'],
      endpoints: {
        authorization: 'https://idp.example.com/authorize',
        token: 'https://idp.example.com/token',
        jwks: 'https://idp.example.com/jwks',
        userinfo: 'https://idp.example.com/userinfo',
        issParameterSupported: true,
      },
      responseMode: 'form_post',
      idTokenSigningAlgorithms: ['ES256'],
      fetchUserinfo: true,
      tenantIssuer: { template: 'https://idp.example.com/{tenantid}/v2', tenantClaim: 'tid' },
    };
    expect(upstreamOidcClientConfigSchema.safeParse(config).success).toBe(true);
  });
});
