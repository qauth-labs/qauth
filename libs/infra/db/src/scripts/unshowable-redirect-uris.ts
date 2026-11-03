/**
 * The operator's list of the clients whose redirect URIs the consent screen
 * cannot show (#914).
 *
 * Since #593 every registration path refuses a redirect URI the consent
 * screen cannot describe (`redirectTarget` in shared-validation). A client
 * stored before that can still hold one, and breaks: a CIMD client at its
 * document's next fetch (also at the token endpoint), a seed manifest that
 * names it is refused whole, and any other client's new users get
 * `invalid_request` from the screen. This lists them per realm, says why each
 * URI fails, and who can replace it. It only reads.
 *
 * The logic lives here, apart from the CLI in
 * `list-unshowable-redirect-uris.ts`, so it can be tested without running the
 * script.
 */
import type { RedirectTargetRefusal } from '@qauth-labs/shared-validation';
import { eq } from 'drizzle-orm';
import type { NodePgDatabase } from 'drizzle-orm/node-postgres';

import { createOAuthClientsRepository } from '../lib/repositories/oauth-clients.repository';
import { realms } from '../lib/schema/core';
import type {
  ClientWithUnshowableRedirectUris,
  Database,
  RedirectUriSource,
  UnshowableRedirectUriScan,
} from '../types';

export interface ListUnshowableArgs {
  /** One realm's clients only, by name; every realm's when absent. */
  realm?: string;
}

export const LIST_UNSHOWABLE_USAGE =
  'Usage: list-unshowable-redirect-uris.ts [--realm=<realm name>]\n' +
  '       Lists the clients with a redirect URI the consent screen cannot show,\n' +
  "       per realm, or only the named realm's. Set DATABASE_URL in the environment.";

/**
 * The exit codes: `0` when no client holds such a URI, `1` when the list is
 * not empty, `2` on a usage error, `3` when the list could not be made (the
 * database unreachable or failing, the realm not found). An upgrade script
 * can so stop on `1`.
 */
export const LIST_UNSHOWABLE_EXIT = { none: 0, found: 1, usage: 2, cannotRun: 3 } as const;

/**
 * Parse `[--realm=<name>]` from `process.argv`. Returns null on an unknown
 * flag or an empty realm name, so the caller prints the usage instead of
 * guessing.
 */
export function parseListUnshowableArgs(argv: readonly string[]): ListUnshowableArgs | null {
  let realm: string | undefined;
  for (const arg of argv.slice(2)) {
    if (arg.startsWith('--realm=')) {
      realm = arg.slice('--realm='.length);
      if (realm === '') return null;
    } else return null;
  }
  return realm === undefined ? {} : { realm };
}

export type ListUnshowableResult =
  | { status: 'realm_not_found' }
  | { status: 'listed'; scan: UnshowableRedirectUriScan };

/** Any drizzle node-postgres database, whatever schema generic it was built with. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type OperatorDb = NodePgDatabase<any>;

/**
 * Every client (of the named realm, or of every realm) with a redirect URI
 * the consent screen cannot show. Reads every client; writes nothing.
 */
export async function listUnshowableRedirectUris(
  db: OperatorDb,
  args: ListUnshowableArgs
): Promise<ListUnshowableResult> {
  let realmId: string | undefined;
  if (args.realm !== undefined) {
    const [realm] = await db
      .select({ id: realms.id })
      .from(realms)
      .where(eq(realms.name, args.realm))
      .limit(1);
    if (!realm) return { status: 'realm_not_found' };
    realmId = realm.id;
  }
  // The tool's database handle has a schema generic of its own; at run time
  // it is the same node-postgres database the repository takes.
  const scan = await createOAuthClientsRepository(
    db as unknown as Database
  ).findUnshowableRedirectUris(realmId === undefined ? {} : { realmId });
  return { status: 'listed', scan };
}

/** Why the consent screen cannot show a URI, for each refusal. */
const REASONS: Readonly<Record<RedirectTargetRefusal, string>> = {
  unparseable: 'not a URL',
  ip_literal: 'its host is an IPv6 address that is not loopback',
  host: 'its host is not a DNS name of valid labels (an underscore, an empty label, a label over 63 characters or with a hyphen at either end)',
  scheme: 'its scheme is longer than 64 characters',
};

/** How the client's redirect URIs are replaced, by who can change them. */
export const REDIRECT_URI_FIXES: Readonly<Record<RedirectUriSource, string>> = {
  cimd:
    'a CIMD client: its owner replaces the URI in its metadata document. Until then its next ' +
    'document fetch fails, at the consent screen and at the token endpoint.',
  operator:
    'operator-provisioned: replace the URI in its seed manifest entry and run ' +
    'db:seed-oauth-clients with --rotate (which also issues a new secret), or update ' +
    'oauth_clients.redirect_uris by hand. Until then a manifest that names the URI is refused whole.',
  developer: 'owned by a developer: its owner replaces the URI through PATCH /api/clients/:id.',
  dynamic:
    'registered dynamically: such a client cannot change its redirect URIs, so it registers ' +
    'again with URIs the screen can show.',
  other:
    'made by hand or by an older release: replace the URI in oauth_clients.redirect_uris, or ' +
    'delete the client.',
};

const REGISTRATIONS: Readonly<Record<RedirectUriSource, string>> = {
  cimd: 'CIMD',
  operator: 'operator-provisioned',
  developer: 'developer-owned',
  dynamic: 'dynamic registration',
  other: 'unmarked',
};

/**
 * Quoted as a JSON string: a client id, realm name or URI stored before
 * #593 may carry control characters, which this prints escaped rather than
 * sends to the operator's terminal.
 */
function quoted(value: string): string {
  return JSON.stringify(value);
}

function plural(count: number, one: string, many: string): string {
  return `${count} ${count === 1 ? one : many}`;
}

/** The report the CLI prints: one block per realm, one entry per client. */
export function describeUnshowableRedirectUris(scan: UnshowableRedirectUriScan): string {
  if (scan.clients.length === 0) {
    return `No client holds a redirect URI the consent screen cannot show (${plural(scan.scanned, 'client', 'clients')} read).`;
  }
  const lines: string[] = [];
  let realmId: string | undefined;
  const realmIds = new Set<string>();
  for (const client of scan.clients) {
    if (client.realmId !== realmId) {
      realmId = client.realmId;
      realmIds.add(realmId);
      if (lines.length > 0) lines.push('');
      lines.push(`Realm ${quoted(client.realmName)} (${client.realmId})`);
    }
    lines.push(...describeClient(client));
  }
  lines.push(
    '',
    `${plural(scan.clients.length, 'client', 'clients')} in ${plural(realmIds.size, 'realm', 'realms')} ` +
      `${scan.clients.length === 1 ? 'holds' : 'hold'} a redirect URI the consent screen cannot show ` +
      `(${plural(scan.scanned, 'client', 'clients')} read). The screen refuses such a URI with ` +
      'invalid_request; replace each one as its client says.'
  );
  return lines.join('\n');
}

function describeClient(client: ClientWithUnshowableRedirectUris): string[] {
  return [
    `  client ${quoted(client.clientId)} (${REGISTRATIONS[client.source]})`,
    ...client.redirectUris.map((entry) => `    ${quoted(entry.uri)}: ${REASONS[entry.reason]}`),
    `    To fix: ${REDIRECT_URI_FIXES[client.source]}`,
  ];
}
