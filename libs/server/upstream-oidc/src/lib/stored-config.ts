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
 *   `context` names the realm and the provider, so a ciphertext copied to
 *   another provider's row, or another realm's, does not decrypt.
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
 * `upstream-oidc:client-secret:<realm id>:<provider type>`. It is not the
 * delivery role's `delivery:` prefix, so the role that sends events and
 * webhooks cannot decrypt a provider's secret.
 */
export const UPSTREAM_CLIENT_SECRET_CONTEXT_PREFIX = 'upstream-oidc:client-secret:';

/** The ciphertext context of one provider's client secret in one realm. */
export function upstreamClientSecretContext(realmId: string, providerId: string): string {
  if (typeof realmId !== 'string' || realmId === '' || realmId.includes(':')) {
    throw new TypeError('realmId must be a non-empty id without ":"');
  }
  if (typeof providerId !== 'string' || providerId === '' || providerId.includes(':')) {
    throw new TypeError('providerId must be a non-empty provider type without ":"');
  }
  return `${UPSTREAM_CLIENT_SECRET_CONTEXT_PREFIX}${realmId}:${providerId}`;
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

/** The schema of a stored config: the parsed config with the secret sealed. */
export const storedUpstreamOidcConfigSchema = z.strictObject({
  issuer: z.string(),
  clientId: z.string(),
  clientAuthentication: z.discriminatedUnion('method', [
    z.strictObject({ method: z.literal('client_secret_basic'), clientSecretSealed: sealedSecret }),
    z.strictObject({ method: z.literal('client_secret_post'), clientSecretSealed: sealedSecret }),
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
  const context = upstreamClientSecretContext(owner.realmId, owner.providerId);
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
 * @throws whatever `cipher.decrypt` throws (a ciphertext of another realm or
 *   provider, a changed one, a caller role that may not decrypt)
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
    const plaintext = await cipher.decrypt(owner.caller, {
      realmId: owner.realmId,
      ciphertext: authentication.clientSecretSealed,
      context: upstreamClientSecretContext(owner.realmId, owner.providerId),
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
