import type { AuthMethodEgress } from '@qauth-labs/server-federation';

import {
  discoveryUrl,
  type UpstreamIdTokenAlgorithm,
  type UpstreamOidcConfig,
  upstreamUrlProblem,
} from './config';
import { invalidResponse } from './errors';
import {
  jsonObjectBody,
  UPSTREAM_OIDC_CALL_CAPS,
  UPSTREAM_OIDC_PURPOSES,
  upstreamCall,
} from './upstream-call';

/**
 * What the client knows of a provider: its endpoints and the few facts of
 * its metadata the client acts on, from the discovery document or from the
 * endpoints set by hand.
 */
export interface UpstreamProviderMetadata {
  /** The configured issuer, which the discovery document matched. */
  readonly issuer: string;
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
  readonly jwksUri: string;
  readonly userinfoEndpoint?: string;
  /** Whether a response without `iss` is refused (RFC 9207 §2.4). */
  readonly issParameterSupported: boolean;
  /**
   * The ID token algorithms to accept: the config's, narrowed to those the
   * provider says it signs with when its metadata lists them.
   */
  readonly idTokenSigningAlgorithms: readonly UpstreamIdTokenAlgorithm[];
  /**
   * The egress source of every endpoint above: `admin` for endpoints the
   * config names, `remote_document` for discovered ones, which the egress
   * allowlist never opens (ADR-019 Decision 8).
   */
  readonly endpointSource: 'admin' | 'remote_document';
}

/** The discovery document's URL members the client calls. */
const DISCOVERED_URL_MEMBERS = [
  'authorization_endpoint',
  'token_endpoint',
  'jwks_uri',
  'userinfo_endpoint',
] as const;

/**
 * The provider's metadata for `config`: from its endpoints when the config
 * sets them by hand, else from its discovery document, which `loadDocument`
 * reads ({@link fetchDiscoveryDocument}, or a cached copy of what it read).
 * The document is checked against the config at every use, so a config
 * change applies at once.
 *
 * @throws UpstreamOidcError when discovery fails or the document fails a check
 */
export async function resolveProviderMetadata(
  config: UpstreamOidcConfig,
  loadDocument: () => Promise<Record<string, unknown>>
): Promise<UpstreamProviderMetadata> {
  const metadata =
    config.endpoints === undefined
      ? parseDiscoveryDocument(await loadDocument(), config)
      : configuredProviderMetadata(config);
  return checkedForConfig(metadata, config);
}

/** The metadata of a provider whose endpoints the config sets by hand. */
function configuredProviderMetadata(config: UpstreamOidcConfig): UpstreamProviderMetadata {
  // The schema has checked every URL; `endpoints` is set on this path.
  const endpoints = config.endpoints as NonNullable<UpstreamOidcConfig['endpoints']>;
  return Object.freeze({
    issuer: config.issuer,
    authorizationEndpoint: endpoints.authorization,
    tokenEndpoint: endpoints.token,
    jwksUri: endpoints.jwks,
    ...(endpoints.userinfo === undefined ? {} : { userinfoEndpoint: endpoints.userinfo }),
    issParameterSupported: endpoints.issParameterSupported,
    idTokenSigningAlgorithms: Object.freeze([...config.idTokenSigningAlgorithms]),
    endpointSource: 'admin',
  });
}

/**
 * Read the provider's discovery document (OpenID Connect Discovery 1.0 §4):
 * a `200` answer with a JSON object, within its caps. Its URL is built from
 * the configured issuer, so it is an `admin` destination; every URL the
 * document names is a `remote_document` one ({@link parseDiscoveryDocument}).
 *
 * @throws UpstreamOidcError `upstream_unavailable` when the document cannot
 *   be read, `invalid_response` when the answer is not a JSON object
 */
export async function fetchDiscoveryDocument(
  egress: AuthMethodEgress,
  issuer: string
): Promise<Record<string, unknown>> {
  const purpose = UPSTREAM_OIDC_PURPOSES.discovery;
  const response = await upstreamCall(egress, {
    method: 'GET',
    url: discoveryUrl(issuer),
    headers: { accept: 'application/json' },
    purpose,
    source: 'admin',
    caps: UPSTREAM_OIDC_CALL_CAPS.discovery,
  });
  if (response.status !== 200) {
    throw invalidResponse(`${purpose}: the provider answered ${response.status}`);
  }
  return jsonObjectBody(response, purpose);
}

/**
 * Check a discovery document against `config` and take what the client
 * needs from it. Every URL it names is a `remote_document` destination,
 * which the egress allowlist never opens (ADR-019 Decision 8).
 *
 * The checks:
 *
 * - `issuer` equals the configured issuer byte for byte (Discovery §4.3),
 *   which also stops one provider's document answering for another;
 * - `authorization_endpoint`, `token_endpoint` and `jwks_uri` are present,
 *   and every URL the client calls is an absolute `https` URL with no
 *   credentials and no fragment; the egress client checks its addresses at
 *   each call;
 * - when the document lists `code_challenge_methods_supported`, it holds
 *   `S256`: QAuth sends PKCE with S256 only;
 * - when it lists `token_endpoint_auth_methods_supported`, it holds the
 *   configured method; when it lists `response_modes_supported`, it holds
 *   the configured mode.
 *
 * @throws UpstreamOidcError `invalid_response` when the document fails a check
 */
export function parseDiscoveryDocument(
  document: Record<string, unknown>,
  config: UpstreamOidcConfig
): UpstreamProviderMetadata {
  const purpose = UPSTREAM_OIDC_PURPOSES.discovery;
  const member = (name: string): unknown =>
    Object.hasOwn(document, name) ? document[name] : undefined;

  if (member('issuer') !== config.issuer) {
    throw invalidResponse(`${purpose}: the document's issuer is not the configured issuer`);
  }
  for (const name of DISCOVERED_URL_MEMBERS) {
    const value = member(name);
    if (value === undefined && name === 'userinfo_endpoint') continue;
    const problem = upstreamUrlProblem(value);
    if (problem !== undefined) {
      throw invalidResponse(`${purpose}: the document's ${name} ${problem}`);
    }
  }
  const listed = (name: string): readonly string[] | undefined => {
    const value = member(name);
    if (value === undefined) return undefined;
    if (!Array.isArray(value) || !value.every((item) => typeof item === 'string')) {
      throw invalidResponse(`${purpose}: the document's ${name} is not a list of strings`);
    }
    return value as string[];
  };
  const challengeMethods = listed('code_challenge_methods_supported');
  if (challengeMethods !== undefined && !challengeMethods.includes('S256')) {
    throw invalidResponse(`${purpose}: the provider does not support PKCE with S256`);
  }
  const authMethods = listed('token_endpoint_auth_methods_supported');
  if (authMethods !== undefined && !authMethods.includes(config.clientAuthentication.method)) {
    throw invalidResponse(
      `${purpose}: the provider does not support ${config.clientAuthentication.method}`
    );
  }
  const responseModes = listed('response_modes_supported');
  if (responseModes !== undefined && !responseModes.includes(config.responseMode)) {
    throw invalidResponse(`${purpose}: the provider does not support ${config.responseMode}`);
  }
  const signingAlgorithms = listed('id_token_signing_alg_values_supported');
  const issParameter = member('authorization_response_iss_parameter_supported');
  if (issParameter !== undefined && typeof issParameter !== 'boolean') {
    throw invalidResponse(
      `${purpose}: the document's authorization_response_iss_parameter_supported is not a boolean`
    );
  }
  const userinfo = member('userinfo_endpoint') as string | undefined;
  return Object.freeze({
    issuer: config.issuer,
    authorizationEndpoint: member('authorization_endpoint') as string,
    tokenEndpoint: member('token_endpoint') as string,
    jwksUri: member('jwks_uri') as string,
    ...(userinfo === undefined ? {} : { userinfoEndpoint: userinfo }),
    issParameterSupported: issParameter === true,
    idTokenSigningAlgorithms: Object.freeze(
      signingAlgorithms === undefined
        ? [...config.idTokenSigningAlgorithms]
        : config.idTokenSigningAlgorithms.filter((algorithm) =>
            signingAlgorithms.includes(algorithm)
          )
    ),
    endpointSource: 'remote_document',
  });
}

/** The checks between the metadata and the rest of the config. */
function checkedForConfig(
  metadata: UpstreamProviderMetadata,
  config: UpstreamOidcConfig
): UpstreamProviderMetadata {
  if (metadata.idTokenSigningAlgorithms.length === 0) {
    throw invalidResponse(
      'the provider signs ID tokens with none of the algorithms the config allows'
    );
  }
  if (config.fetchUserinfo && metadata.userinfoEndpoint === undefined) {
    throw invalidResponse('the config reads userinfo, and the provider names no userinfo endpoint');
  }
  return metadata;
}
