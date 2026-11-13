import type { UpstreamAssertionAlgorithm, UpstreamOidcPreset } from '@qauth-labs/server-federation';

import { upstreamOidcClientConfigSchema } from './config';

/**
 * WHOSE CLIENT A PROVIDER'S CLIENT ASSERTIONS SPEAK FOR (#1073): the client
 * id QAuth is registered under at the provider, the `iss` of its signed
 * client secret when that is not the client id, and the algorithm of the key
 * registered there.
 *
 * The signer role signs a client assertion (`private_key_jwt`) or a signed
 * client secret with the realm's `upstream_client_assertion` key for the
 * provider, and sets `iss` and `sub` itself, from the realm's stored record
 * of the provider, never from the signing request. A preset makes its
 * provider config with its own code, which the signer's process never loads,
 * so the admin API derives the record with {@link upstreamOidcPresetAssertionClient}
 * when it writes the realm's configuration of the preset, and stores it
 * beside it, where the signer reads it.
 */
export interface UpstreamAssertionClient {
  /** The client id at the provider: the assertion's `sub`, and its `iss` unless {@link assertionIssuer} is set. */
  readonly clientId: string;
  /** The `iss` of a signed client secret that is not the client id, such as Sign in with Apple's Team ID. */
  readonly assertionIssuer?: string;
  /** The algorithm of the key registered with the provider: the key the signer signs with. */
  readonly algorithm: UpstreamAssertionAlgorithm;
}

/**
 * The assertion client of a parsed provider config, or `undefined` for one
 * that authenticates with a client secret, and so has the signer sign
 * nothing.
 */
export function upstreamAssertionClientOf(config: {
  readonly clientId: string;
  readonly clientAuthentication:
    | { readonly method: 'client_secret_basic' | 'client_secret_post' }
    | { readonly method: 'private_key_jwt'; readonly signingAlgorithm: UpstreamAssertionAlgorithm }
    | {
        readonly method: 'signed_client_secret';
        readonly signingAlgorithm: UpstreamAssertionAlgorithm;
        readonly assertionIssuer?: string | undefined;
      };
}): UpstreamAssertionClient | undefined {
  const authentication = config.clientAuthentication;
  switch (authentication.method) {
    case 'private_key_jwt':
      return Object.freeze({
        clientId: config.clientId,
        algorithm: authentication.signingAlgorithm,
      });
    case 'signed_client_secret':
      return Object.freeze({
        clientId: config.clientId,
        ...(authentication.assertionIssuer === undefined
          ? {}
          : { assertionIssuer: authentication.assertionIssuer }),
        algorithm: authentication.signingAlgorithm,
      });
    default:
      return undefined;
  }
}

/**
 * The assertion client of a preset for one realm's `config`, parsed by the
 * preset's method (`createUpstreamOidcPresetMethod`): the provider config the
 * preset's `upstreamConfig` makes for it, parsed as the client parses it.
 * `undefined` when the provider config authenticates with a client secret.
 *
 * @throws TypeError when `upstreamConfig` throws or makes a provider config
 *   that does not parse: the method's config schema refuses such a config
 *   first, so reaching this is a preset whose mapping is not pure
 */
export function upstreamOidcPresetAssertionClient<TConfig>(
  preset: Pick<UpstreamOidcPreset<TConfig>, 'type' | 'upstreamConfig'>,
  config: TConfig
): UpstreamAssertionClient | undefined {
  let made: unknown;
  try {
    made = preset.upstreamConfig(config);
  } catch {
    throw new TypeError(`The preset ${preset.type} could not make its provider config`);
  }
  const parsed = upstreamOidcClientConfigSchema.safeParse(made);
  if (!parsed.success) {
    throw new TypeError(`The preset ${preset.type} made a provider config that does not parse`);
  }
  return upstreamAssertionClientOf(parsed.data);
}
