import { createHash } from 'node:crypto';

import { UPSTREAM_CLIENT_SECRET_CONTEXT_PREFIX } from '@qauth-labs/server-keys';
import { z } from 'zod';

import {
  upstreamEndpointsSchema,
  type UpstreamOidcConfig,
  type UpstreamOidcConfigInput,
  upstreamOidcConfigSchema,
} from './config';

/**
 * A provider's config as it is stored (#601): the client secret encrypted
 * with the realm's data-at-rest key, through the signer role (ADR-019
 * Decision 9), and never returned.
 *
 * - {@link sealUpstreamOidcConfig} parses an admin's config and replaces
 *   `clientSecret` with `clientSecretSealed`, the signer's ciphertext. Its
 *   `context` names the realm, the provider and where the secret is sent
 *   (its issuer, and its token endpoint when set by hand), so a ciphertext
 *   copied to another provider's row, or another realm's, does not decrypt,
 *   and neither does one whose config was pointed at another host.
 * - {@link openUpstreamOidcConfig} decrypts it again, for the context the
 *   host builds a method's context from (`createAuthMethodContext`).
 * - {@link describeUpstreamOidcConfig} is the view an API or an event may
 *   carry: the secret is neither there nor its ciphertext, only the fact that
 *   one is set.
 *
 * Where the stored form lives (the realm's provider rows) is the provider
 * administration's (#714) and the plugin runtime's (#600).
 */

/**
 * The start of every client secret's ciphertext context:
 * `upstream-oidc:client-secret:<realm id>:<provider type>:<destination>`.
 * The signer's policy defines it (`@qauth-labs/server-keys`): the `api` role
 * may decrypt a context under it, and `web` and `delivery` may not, so the
 * host opens a stored config as `api`, or as `local` in a single deployment.
 */
export { UPSTREAM_CLIENT_SECRET_CONTEXT_PREFIX };

/** A destination digest: SHA-256, lower-case hex. */
const DESTINATION_DIGEST = /^[0-9a-f]{64}$/;

/**
 * Where a provider's client secret is sent, as a SHA-256 hex digest: the
 * issuer, and the token endpoint when the config sets the endpoints by
 * hand, as a JSON pair (`null` for a discovered token endpoint), so no two
 * pairs share an encoding. A discovered token endpoint is not part of it:
 * discovery reads the configured issuer's own document, whose `issuer` must
 * match. An admin who cannot read the write-only secret therefore cannot
 * send it to another host by changing either value: the stored secret no
 * longer opens, and must be entered again.
 */
export function upstreamClientSecretDestination(config: {
  readonly issuer: string;
  readonly endpoints?: { readonly token: string };
}): string {
  return createHash('sha256')
    .update(JSON.stringify([config.issuer, config.endpoints?.token ?? null]), 'utf8')
    .digest('hex');
}

/**
 * The ciphertext context of one provider's client secret in one realm, for
 * one destination ({@link upstreamClientSecretDestination}).
 */
export function upstreamClientSecretContext(
  realmId: string,
  providerId: string,
  destination: string
): string {
  if (typeof realmId !== 'string' || realmId === '' || realmId.includes(':')) {
    throw new TypeError('realmId must be a non-empty id without ":"');
  }
  if (typeof providerId !== 'string' || providerId === '' || providerId.includes(':')) {
    throw new TypeError('providerId must be a non-empty provider type without ":"');
  }
  if (typeof destination !== 'string' || !DESTINATION_DIGEST.test(destination)) {
    throw new TypeError('destination must be a SHA-256 hex digest');
  }
  return `${UPSTREAM_CLIENT_SECRET_CONTEXT_PREFIX}${realmId}:${providerId}:${destination}`;
}

/**
 * The two operations of the signer role the codec uses (`Signer.encrypt`
 * and `Signer.decrypt` of `@qauth-labs/server-keys`), each naming its caller
 * role, as the signer's do.
 */
export interface UpstreamSecretCipher {
  encrypt(
    caller: string,
    request: { readonly realmId: string; readonly plaintext: Uint8Array; readonly context?: string }
  ): Promise<string>;
  decrypt(
    caller: string,
    request: { readonly realmId: string; readonly ciphertext: string; readonly context?: string }
  ): Promise<Uint8Array>;
}

/** Which realm and provider a stored config belongs to, and who asks. */
export interface UpstreamSecretOwner {
  readonly realmId: string;
  /** The provider's `type`, `oidc_<alias>`. */
  readonly providerId: string;
  /** The signer caller role the call is made for, such as `api`. */
  readonly caller: string;
}

/** A ciphertext as `Signer.encrypt` returns it: `v1.<kid>.<iv>.<ciphertext>`. */
const sealedSecret = z
  .string()
  .max(16 * 1024)
  .regex(/^v1\.[A-Za-z0-9_.-]+$/);

/**
 * The destination a secret was sealed for ({@link upstreamClientSecretDestination}).
 * Kept so a changed issuer or token endpoint is told apart from a broken
 * ciphertext; the context binds it either way.
 */
const sealedDestination = z.string().regex(DESTINATION_DIGEST);

/** The schema of a stored config: the parsed config with the secret sealed. */
export const storedUpstreamOidcConfigSchema = z.strictObject({
  issuer: z.string(),
  clientId: z.string(),
  clientAuthentication: z.discriminatedUnion('method', [
    z.strictObject({
      method: z.literal('client_secret_basic'),
      clientSecretSealed: sealedSecret,
      clientSecretDestination: sealedDestination,
    }),
    z.strictObject({
      method: z.literal('client_secret_post'),
      clientSecretSealed: sealedSecret,
      clientSecretDestination: sealedDestination,
    }),
    z.strictObject({
      method: z.literal('private_key_jwt'),
      signingAlgorithm: z.enum(['RS256', 'ES256', 'EdDSA']),
    }),
  ]),
  scopes: z.array(z.string()),
  endpoints: upstreamEndpointsSchema.optional(),
  responseMode: z.enum(['query', 'form_post']),
  idTokenSigningAlgorithms: z.array(z.string()),
  fetchUserinfo: z.boolean(),
});

/** A provider's config as stored. */
export type StoredUpstreamOidcConfig = z.output<typeof storedUpstreamOidcConfigSchema>;

/** A provider's config as an API may show it: no secret, no ciphertext. */
export type UpstreamOidcConfigView = Omit<StoredUpstreamOidcConfig, 'clientAuthentication'> & {
  readonly clientAuthentication:
    | {
        readonly method: 'client_secret_basic' | 'client_secret_post';
        readonly clientSecretSet: true;
      }
    | { readonly method: 'private_key_jwt'; readonly signingAlgorithm: string };
};

/**
 * A stored client secret opened under a config that sends it elsewhere: the
 * issuer, or the token endpoint set by hand, is not the one the secret was
 * sealed for. It does not decrypt; the secret must be entered again with the
 * new config.
 */
export class UpstreamClientSecretDestinationChangedError extends Error {
  constructor() {
    super('the client secret was stored for another issuer or token endpoint: enter it again');
    this.name = 'UpstreamClientSecretDestinationChangedError';
    Object.setPrototypeOf(this, UpstreamClientSecretDestinationChangedError.prototype);
  }
}

/** A config that does not parse; `issues` names members, never their values. */
export class UpstreamOidcConfigError extends Error {
  readonly issues: readonly string[];

  constructor(issues: readonly string[]) {
    super('the upstream OIDC provider config does not parse');
    this.name = 'UpstreamOidcConfigError';
    this.issues = Object.freeze([...issues]);
    Object.setPrototypeOf(this, UpstreamOidcConfigError.prototype);
  }
}

function parsed<T>(schema: z.ZodType<T>, value: unknown): T {
  const result = schema.safeParse(value);
  if (!result.success) {
    throw new UpstreamOidcConfigError(
      result.error.issues.map((issue) => `${issue.path.join('.') || '(root)'}: ${issue.code}`)
    );
  }
  return result.data;
}

/**
 * Parse an admin's config and encrypt its client secret, for storage.
 *
 * @throws UpstreamOidcConfigError when the config does not parse
 * @throws whatever `cipher.encrypt` throws (no data-at-rest key, a caller
 *   role that may not encrypt)
 */
export async function sealUpstreamOidcConfig(
  cipher: UpstreamSecretCipher,
  owner: UpstreamSecretOwner,
  config: UpstreamOidcConfigInput | unknown
): Promise<StoredUpstreamOidcConfig> {
  const parsedConfig = parsed(upstreamOidcConfigSchema, config);
  const destination = upstreamClientSecretDestination(parsedConfig);
  const context = upstreamClientSecretContext(owner.realmId, owner.providerId, destination);
  const authentication = parsedConfig.clientAuthentication;
  const stored: StoredUpstreamOidcConfig = {
    ...parsedConfig,
    clientAuthentication:
      authentication.method === 'private_key_jwt'
        ? authentication
        : {
            method: authentication.method,
            clientSecretSealed: await cipher.encrypt(owner.caller, {
              realmId: owner.realmId,
              plaintext: Buffer.from(authentication.clientSecret, 'utf8'),
              context,
            }),
            clientSecretDestination: destination,
          },
  };
  return parsed(storedUpstreamOidcConfigSchema, stored);
}

/**
 * Decrypt a stored config's client secret: the config a method's context is
 * built from.
 *
 * @throws UpstreamOidcConfigError when the stored config, or the config it
 *   opens to, does not parse
 * @throws UpstreamClientSecretDestinationChangedError when the config's
 *   issuer, or its token endpoint set by hand, is not the one the secret was
 *   sealed for; nothing is decrypted
 * @throws whatever `cipher.decrypt` throws (a ciphertext of another realm,
 *   provider or destination, a changed one, a caller role that may not
 *   decrypt)
 */
export async function openUpstreamOidcConfig(
  cipher: UpstreamSecretCipher,
  owner: UpstreamSecretOwner,
  stored: unknown
): Promise<UpstreamOidcConfig> {
  const storedConfig = parsed(storedUpstreamOidcConfigSchema, stored);
  const authentication = storedConfig.clientAuthentication;
  let clientAuthentication: UpstreamOidcConfigInput['clientAuthentication'];
  if (authentication.method === 'private_key_jwt') {
    clientAuthentication = authentication as UpstreamOidcConfigInput['clientAuthentication'];
  } else {
    // The context is built from the config as it is now: a recorded
    // destination edited to match a changed config still does not decrypt.
    const destination = upstreamClientSecretDestination(storedConfig);
    if (authentication.clientSecretDestination !== destination) {
      throw new UpstreamClientSecretDestinationChangedError();
    }
    const plaintext = await cipher.decrypt(owner.caller, {
      realmId: owner.realmId,
      ciphertext: authentication.clientSecretSealed,
      context: upstreamClientSecretContext(owner.realmId, owner.providerId, destination),
    });
    clientAuthentication = {
      method: authentication.method,
      clientSecret: new TextDecoder('utf-8', { fatal: true }).decode(plaintext),
    };
  }
  return parsed(upstreamOidcConfigSchema, { ...storedConfig, clientAuthentication });
}

/**
 * The view of a stored config an API, an event or a diff may carry: the
 * secret's ciphertext is left out, and only `clientSecretSet: true` says
 * one is set.
 *
 * @throws UpstreamOidcConfigError when the stored config does not parse
 */
export function describeUpstreamOidcConfig(stored: unknown): UpstreamOidcConfigView {
  const storedConfig = parsed(storedUpstreamOidcConfigSchema, stored);
  const authentication = storedConfig.clientAuthentication;
  return {
    ...storedConfig,
    clientAuthentication:
      authentication.method === 'private_key_jwt'
        ? { method: 'private_key_jwt', signingAlgorithm: authentication.signingAlgorithm }
        : { method: authentication.method, clientSecretSet: true },
  };
}
