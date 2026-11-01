import type { AuthMethodEgress, AuthMethodEgressResponse } from '@qauth-labs/server-federation';

import { type UpstreamOidcConfig, upstreamOidcConfigSchema } from './config';
import { UpstreamOidcError } from './errors';
import {
  fetchDiscoveryDocument,
  resolveProviderMetadata,
  type UpstreamProviderMetadata,
} from './metadata';
import { UPSTREAM_OIDC_PURPOSES } from './upstream-call';

/**
 * The check a provider's config gets when it is registered or changed
 * (ADR-019 Decision 8: "checked when it is registered and again at every
 * delivery"): discovery, as the method runs it, and then every endpoint URL
 * through the egress client's address checks, without calling it. The
 * provider administration (#714) runs it from its create, update and
 * `testProvider` operations; the method checks again at each use, since
 * every call goes through the egress client.
 *
 * It takes the host's whole egress client, with `validateDestination`, which
 * a method's context never holds.
 */

/** The parts of the egress client of `@qauth-labs/server-egress` the check uses. */
export interface UpstreamRegistrationEgress {
  request(request: {
    method: 'GET' | 'POST';
    url: string;
    headers?: Record<string, string>;
    body?: string | Uint8Array;
    purpose: string;
    source: 'operator' | 'admin' | 'remote_document';
    realm?: string;
    limits?: { maxRedirects: 0 };
  }): Promise<AuthMethodEgressResponse>;
  validateDestination(
    url: string,
    options: { purpose: string; source: 'admin' | 'remote_document'; realm?: string }
  ): Promise<unknown>;
}

/**
 * What the check found:
 *
 * - `invalid_config`: the config does not parse (`detail` names members);
 * - `discovery_unavailable`: the discovery document could not be read;
 * - `invalid_document`: the document fails a check, its `issuer` among them;
 * - `destination_refused`: the egress client refuses an endpoint, such as a
 *   discovered one on a private address.
 */
export type UpstreamProviderCheck =
  | { readonly ok: true; readonly metadata: UpstreamProviderMetadata }
  | {
      readonly ok: false;
      readonly finding:
        | 'invalid_config'
        | 'discovery_unavailable'
        | 'invalid_document'
        | 'destination_refused';
      readonly detail: string;
    };

/**
 * Check a provider's config for `realm` (by name: the allowlist entries that
 * name it apply to the `admin` destinations). Never throws for a finding.
 */
export async function checkUpstreamOidcProvider(
  egress: UpstreamRegistrationEgress,
  realm: string,
  config: unknown
): Promise<UpstreamProviderCheck> {
  const parsed = upstreamOidcConfigSchema.safeParse(config);
  if (!parsed.success) {
    return {
      ok: false,
      finding: 'invalid_config',
      detail: parsed.error.issues
        .map((issue) => `${issue.path.join('.') || '(root)'}: ${issue.code}`)
        .join('; '),
    };
  }
  const providerConfig: UpstreamOidcConfig = parsed.data;
  // The same adapter as a method's context: this realm, and the zero
  // redirect cap when a call asks for it.
  const methodEgress: AuthMethodEgress = {
    request: ({ redirect, ...call }) =>
      egress.request({
        ...call,
        ...(call.headers === undefined ? {} : { headers: { ...call.headers } }),
        realm,
        ...(redirect === 'error' ? { limits: { maxRedirects: 0 as const } } : {}),
      }),
  };

  let metadata: UpstreamProviderMetadata;
  try {
    metadata = await resolveProviderMetadata(providerConfig, () =>
      fetchDiscoveryDocument(methodEgress, providerConfig.issuer)
    );
  } catch (error) {
    if (!(error instanceof UpstreamOidcError)) throw error;
    return {
      ok: false,
      finding:
        error.reason === 'upstream_unavailable' ? 'discovery_unavailable' : 'invalid_document',
      detail: error.message,
    };
  }

  const endpoints: [string, string | undefined, string][] = [
    ['authorization endpoint', metadata.authorizationEndpoint, UPSTREAM_OIDC_PURPOSES.discovery],
    ['token endpoint', metadata.tokenEndpoint, UPSTREAM_OIDC_PURPOSES.token],
    ['jwks_uri', metadata.jwksUri, UPSTREAM_OIDC_PURPOSES.jwks],
    ['userinfo endpoint', metadata.userinfoEndpoint, UPSTREAM_OIDC_PURPOSES.userinfo],
  ];
  for (const [name, url, purpose] of endpoints) {
    if (url === undefined) continue;
    try {
      await egress.validateDestination(url, {
        purpose,
        source: metadata.endpointSource,
        realm,
      });
    } catch {
      return {
        ok: false,
        finding: 'destination_refused',
        detail: `the egress client refuses the ${name}${metadata.endpointSource === 'remote_document' ? ', which discovery named and the allowlist never opens' : ''}`,
      };
    }
  }
  return { ok: true, metadata };
}
