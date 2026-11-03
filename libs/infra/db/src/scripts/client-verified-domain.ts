/**
 * Set or clear an operator-provisioned client's verified domain (#914).
 *
 * The consent screen, and every screen that names a client, leads with what
 * the server verified about it (ADR-019 Decision 6, #593). For a client the
 * operator provisioned that is `oauth_clients.verified_domain`; until it is
 * set the screens show the client as an unverified app. The seed manifest
 * writes the column, but writes an existing client only with `--rotate`,
 * which also issues it a new secret. This sets the column alone: the secret,
 * the redirect URIs and every other column stay as they are.
 *
 * The value goes through `normaliseVerifiedDomain`, as the manifest's does:
 * lower case, an internationalised name in its `xn--` form, no trailing dot;
 * a URL, a port, an IP address, a single label and a public suffix (`co.uk`,
 * or a shared-hosting suffix such as `eu.org`) are refused. The database's
 * CHECK (`oauth_clients_verified_domain_form`) holds the form again.
 *
 * Only a client with `provisioned_by_operator` takes one: the screens read
 * the column for no other client, and a CIMD client's verified domain is the
 * host of its client id. Setting it is a security operation of the admin API
 * (`clients.update`, `qauth:admin:security`, ADR-019 Decision 7); until that
 * ships, this is operator tooling that talks to the database directly, like
 * `seed-oauth-clients.ts`. The logic lives here, apart from the CLI in
 * `set-client-verified-domain.ts`, so it can be tested without running it.
 */
import {
  InvalidVerifiedDomainError,
  type InvalidVerifiedDomainReason,
  normaliseVerifiedDomain,
} from '@qauth-labs/shared-validation';
import { and, eq, sql } from 'drizzle-orm';
import type { NodePgDatabase } from 'drizzle-orm/node-postgres';

import { oauthClients, realms } from '../lib/schema/core';

export interface VerifiedDomainArgs {
  realm: string;
  clientId: string;
  /** The domain to set, as the operator wrote it; `null` to clear it. */
  domain: string | null;
}

export const VERIFIED_DOMAIN_USAGE =
  'Usage: set-client-verified-domain.ts --realm=<realm name> --client-id=<client_id>\n' +
  '         (--domain=<domain> | --clear)\n' +
  "       Sets an operator-provisioned client's verified domain, or with --clear\n" +
  '       removes it. The client keeps its secret. Set DATABASE_URL in the environment.';

/**
 * Parse `--realm=<name> --client-id=<id> (--domain=<domain> | --clear)` from
 * `process.argv`. Returns null when a required argument is missing, both or
 * neither of `--domain` and `--clear` are given, or an unknown flag is, so
 * the caller prints the usage instead of guessing.
 */
export function parseVerifiedDomainArgs(argv: readonly string[]): VerifiedDomainArgs | null {
  let realm: string | undefined;
  let clientId: string | undefined;
  let domain: string | undefined;
  let clear = false;
  for (const arg of argv.slice(2)) {
    if (arg.startsWith('--realm=')) realm = arg.slice('--realm='.length);
    else if (arg.startsWith('--client-id=')) clientId = arg.slice('--client-id='.length);
    else if (arg.startsWith('--domain=')) domain = arg.slice('--domain='.length);
    else if (arg === '--clear') clear = true;
    else return null;
  }
  if (!realm || !clientId) return null;
  if (clear === (domain !== undefined)) return null;
  if (domain === '') return null;
  return { realm, clientId, domain: clear ? null : (domain as string) };
}

export type VerifiedDomainResult =
  | { status: 'invalid_domain'; reason: InvalidVerifiedDomainReason }
  | { status: 'realm_not_found' }
  | { status: 'client_not_found' }
  /** A CIMD client: its verified domain is the host of its client id. */
  | { status: 'cimd_client'; clientId: string }
  /** Not operator-provisioned: no screen reads the column for it. */
  | { status: 'not_operator_provisioned'; clientId: string }
  | {
      status: 'set' | 'cleared' | 'unchanged';
      id: string;
      clientId: string;
      /** The stored value before the change. */
      previous: string | null;
      /** The stored value now. */
      verifiedDomain: string | null;
    };

/** Any drizzle node-postgres database, whatever schema generic it was built with. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type OperatorDb = NodePgDatabase<any>;

/**
 * Set the client's verified domain to the normalised `args.domain`, or clear
 * it, in one transaction that writes `verified_domain` and `updated_at` only.
 * Idempotent: a client that already holds the value is reported `unchanged`
 * and nothing is written. A value `normaliseVerifiedDomain` refuses is
 * refused before the database is read.
 */
export async function setClientVerifiedDomain(
  db: OperatorDb,
  args: VerifiedDomainArgs
): Promise<VerifiedDomainResult> {
  let verifiedDomain: string | null = null;
  if (args.domain !== null) {
    try {
      verifiedDomain = normaliseVerifiedDomain(args.domain);
    } catch (error) {
      if (error instanceof InvalidVerifiedDomainError) {
        return { status: 'invalid_domain', reason: error.reason };
      }
      throw error;
    }
  }

  return db.transaction(async (tx) => {
    const [realm] = await tx
      .select({ id: realms.id })
      .from(realms)
      .where(eq(realms.name, args.realm))
      .limit(1);
    if (!realm) return { status: 'realm_not_found' as const };

    // FOR UPDATE: a seed run with `--rotate` for the same client, which
    // writes the column from its manifest, waits for this one or this for it.
    const [client] = await tx
      .select({
        id: oauthClients.id,
        clientId: oauthClients.clientId,
        metadata: oauthClients.metadata,
        provisionedByOperator: oauthClients.provisionedByOperator,
        verifiedDomain: oauthClients.verifiedDomain,
      })
      .from(oauthClients)
      .where(and(eq(oauthClients.realmId, realm.id), eq(oauthClients.clientId, args.clientId)))
      .limit(1)
      .for('update');
    if (!client) return { status: 'client_not_found' as const };

    // Clearing works on any client: a value on a client that is not
    // operator-provisioned (written by hand) is shown nowhere, and removing
    // it only tidies the row.
    if (verifiedDomain !== null) {
      if (client.metadata?.['registrationType'] === 'cimd') {
        return { status: 'cimd_client' as const, clientId: client.clientId };
      }
      if (!client.provisionedByOperator) {
        return { status: 'not_operator_provisioned' as const, clientId: client.clientId };
      }
    }

    const previous = client.verifiedDomain;
    if (previous === verifiedDomain) {
      return {
        status: 'unchanged' as const,
        id: client.id,
        clientId: client.clientId,
        previous,
        verifiedDomain,
      };
    }

    await tx
      .update(oauthClients)
      .set({
        verifiedDomain,
        updatedAt: sql`(EXTRACT(EPOCH FROM now()) * 1000)::bigint`,
      })
      .where(eq(oauthClients.id, client.id));

    return {
      status: verifiedDomain === null ? ('cleared' as const) : ('set' as const),
      id: client.id,
      clientId: client.clientId,
      previous,
      verifiedDomain,
    };
  });
}
