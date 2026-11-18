import { REALM_POLICY_REGISTRY } from '@qauth-labs/fastify-plugin-realm-policy';
import type { RealmFileClient } from '@qauth-labs/realm-file';
import type { FastifyRequest } from 'fastify';

import {
  isDynamicallyRegistered,
  metadataDocumentOf,
  type OAuthClientRecord,
  PRIVATE_JWK_MEMBERS,
} from '../clients/representation';
import { adminTransaction } from '../pipeline';
import { readPolicyState, setSecretsOf } from '../realms/operations';
import type { ImportState } from './section';

/**
 * THE REALM AS AN IMPORT READS IT (issue #518): the stored policies, which
 * secret policy fields are set, and every client of the realm, split into
 * those a realm file describes and those it may not name. Read in the admin
 * handler's transaction, so the plan is of one state.
 *
 * A realm file's `clients` are the clients the operator manages (#515): an
 * operator provisioned them (the seed manifest, the admin API), no developer
 * owns them, they did not register themselves and have no metadata
 * document, and they are neither the system client (`system_client`) nor a
 * service account's (the service-accounts command manages those).
 */

/** The members of a JWK that hold private key material: never in a file. */
const PRIVATE_KEY_MEMBERS: ReadonlySet<string> = new Set([...PRIVATE_JWK_MEMBERS, 'priv']);

/** A stored key set with its public members only. */
function publicKeySet(jwks: NonNullable<OAuthClientRecord['jwks']>): RealmFileClient['jwks'] {
  return {
    keys: jwks.keys.map((key) =>
      Object.fromEntries(
        Object.entries(key ?? {}).filter(([member]) => !PRIVATE_KEY_MEMBERS.has(member))
      )
    ),
  } as RealmFileClient['jwks'];
}

/**
 * A stored client as a realm file lists it: each member the seed manifest
 * takes, a member whose column holds nothing (`null`, or an empty list where
 * the column's nothing is `null`) left out, so the entry is one a file may
 * hold. Never its secret.
 */
export function realmFileClientOf(row: OAuthClientRecord): RealmFileClient {
  const entry: Record<string, unknown> = {
    client_id: row.clientId,
    name: row.name,
    grant_types: [...row.grantTypes],
    response_types: [...row.responseTypes],
    scopes: [...row.scopes],
    redirect_uris: [...row.redirectUris],
    post_logout_redirect_uris: [...row.postLogoutRedirectUris],
    backchannel_logout_session_required: row.backchannelLogoutSessionRequired,
    require_pkce: row.requirePkce,
    token_endpoint_auth_method: row.tokenEndpointAuthMethod,
    is_agent: row.isAgent,
    id_jag_targets: [...row.idJagTargets],
    webauthn_allowed_origins: [...(row.webauthnAllowedOrigins as string[])],
    dpop_bound_access_tokens: row.dpopBoundAccessTokens,
    environment: row.environment,
  };
  const optional: Record<string, unknown> = {
    description: row.description,
    client_credentials_scopes: row.clientCredentialsScopes,
    audience: row.audience !== null && row.audience.length > 0 ? row.audience : null,
    backchannel_logout_uri: row.backchannelLogoutUri,
    max_agent_mode: row.maxAgentMode,
    jwks: row.jwks === null ? null : publicKeySet(row.jwks),
    jwks_uri: row.jwksUri,
    verified_domain: row.verifiedDomain,
    first_party_profile: row.firstPartyProfile,
    first_party_policy: row.firstPartyProfile === 'native_backend' ? row.firstPartyPolicy : null,
    first_party_reason: row.firstPartyProfile === null ? null : row.firstPartyReason,
    hosted_flows: row.hostedFlows !== null && row.hostedFlows.length > 0 ? row.hostedFlows : null,
    registration_challenge: row.registrationChallenge === true ? true : null,
  };
  for (const [member, value] of Object.entries(optional)) {
    if (value !== null && value !== undefined) entry[member] = structuredClone(value);
  }
  return entry as unknown as RealmFileClient;
}

/**
 * Why a realm file may not name `row`, or `undefined` when it is a client the
 * file describes.
 */
export function unmanagedReason(
  row: OAuthClientRecord,
  context: { readonly systemClientId: string; readonly serviceAccountClients: ReadonlySet<string> }
): string | undefined {
  if (metadataDocumentOf(row) !== null) {
    return 'a CIMD client, which its metadata document describes';
  }
  if (isDynamicallyRegistered(row)) return 'a client that registered itself';
  if (row.developerId !== null) return 'a client a developer owns';
  if (row.clientId === context.systemClientId) {
    return 'the system client, which the system_client section describes';
  }
  if (context.serviceAccountClients.has(row.id)) {
    return "a service account's client, which the service-accounts command manages";
  }
  if (!row.provisionedByOperator) return 'a client no operator provisioned';
  return undefined;
}

/** How many clients one page reads. */
const PAGE_SIZE = 200;

/** The most clients an import reads from one realm: more is refused rather than read without end. */
export const MAX_IMPORT_CLIENTS = 10_000;

/** A realm with more clients than an import reads. */
export class TooManyClientsError extends Error {
  override readonly name = 'TooManyClientsError';

  constructor() {
    super(`The realm holds more than ${MAX_IMPORT_CLIENTS} clients, more than an import reads`);
  }
}

/** Every client of the realm `realmId`, read page by page in `tx`. */
async function everyClient(
  request: FastifyRequest,
  realmId: string,
  tx: ReturnType<typeof adminTransaction>
): Promise<OAuthClientRecord[]> {
  const rows: OAuthClientRecord[] = [];
  let after: { readonly at: number; readonly id: string } | undefined;
  for (;;) {
    const page = await request.server.repositories.oauthClients.pageByRealm(
      realmId,
      { limit: PAGE_SIZE, ...(after === undefined ? {} : { after }) },
      {},
      tx
    );
    rows.push(...page);
    if (rows.length > MAX_IMPORT_CLIENTS) throw new TooManyClientsError();
    if (page.length < PAGE_SIZE) return rows;
    const last = page[page.length - 1];
    after = { at: last.createdAt, id: last.id };
  }
}

/**
 * The state an import of the realm `realm` is planned against, read in the
 * admin handler's transaction.
 *
 * @throws NotFoundError when the realm is gone
 * @throws TooManyClientsError when the realm holds more clients than an import reads
 */
export async function readImportState(
  request: FastifyRequest,
  realm: { readonly id: string; readonly name: string },
  systemClientId: string
): Promise<ImportState> {
  const tx = adminTransaction(request);
  const policies = await readPolicyState(request, realm.id, tx);
  const rows = await everyClient(request, realm.id, tx);
  const accounts = await request.server.repositories.serviceAccounts.list(realm.id, tx);
  const serviceAccountClients = new Set(accounts.map((account) => account.clientId));
  const clients: RealmFileClient[] = [];
  const unmanagedClients = new Map<string, string>();
  for (const row of rows) {
    const why = unmanagedReason(row, { systemClientId, serviceAccountClients });
    if (why === undefined) clients.push(realmFileClientOf(row));
    else unmanagedClients.set(row.clientId, why);
  }
  return {
    realmId: realm.id,
    realmName: realm.name,
    policiesVersion: policies.version,
    // The representation's `<name>Set` flags are dropped by the `input`
    // view: what remains is the stored document (`policyPatchDiff`).
    policies: REALM_POLICY_REGISTRY.parse(policies.policies, 'input'),
    setSecrets: setSecretsOf(policies.policies),
    clients,
    unmanagedClients,
  };
}
