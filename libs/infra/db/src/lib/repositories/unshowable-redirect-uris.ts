/**
 * The clients that hold a redirect URI the consent screen cannot show (#914).
 *
 * Since #593 the consent screen always says where the authorization code
 * goes (`redirectTarget` in shared-validation), and every registration path
 * refuses a redirect URI it cannot describe. A client stored before that can
 * still hold one, and it breaks: a CIMD client at its document's next fetch, a
 * seed manifest that names it is refused whole, and any other client's new
 * users get `invalid_request` from the screen. This finds them, with the same
 * rule the screen applies, so the list and the screen never disagree.
 *
 * The scan reads every client's redirect URIs, a page at a time in `id`
 * order, and applies the rule here rather than in SQL: the rule is the URL
 * parser's (IDN conversion, IPv4 forms, percent-decoding), which no SQL
 * expression reproduces exactly.
 */
import { redirectTargetRefusal } from '@qauth-labs/shared-validation';

import type {
  ClientWithUnshowableRedirectUris,
  RedirectUriSource,
  UnshowableRedirectUri,
  UnshowableRedirectUriScan,
} from '../../types/repository';

/** A client row, as much of it as the scan reads. */
export interface RedirectUriScanRow {
  id: string;
  realmId: string;
  realmName: string;
  clientId: string;
  redirectUris: unknown;
  metadata: Record<string, unknown> | null;
  provisionedByOperator: boolean;
  developerId: string | null;
}

/** Clients read per page. */
export const REDIRECT_URI_SCAN_PAGE_SIZE = 500;

/** Who can change a client's redirect URIs, from how its row was made. */
export function redirectUriSource(
  row: Pick<RedirectUriScanRow, 'metadata' | 'provisionedByOperator' | 'developerId'>
): RedirectUriSource {
  const registrationType = row.metadata?.['registrationType'];
  if (registrationType === 'cimd') return 'cimd';
  if (row.provisionedByOperator) return 'operator';
  if (row.developerId !== null) return 'developer';
  if (registrationType === 'dynamic') return 'dynamic';
  return 'other';
}

/**
 * The redirect URIs of `redirectUris` the consent screen cannot show, with
 * why. A stored value that is not a list of strings (a row written by hand)
 * has no URI the screen could match a request against, so it yields none.
 */
export function unshowableRedirectUris(redirectUris: unknown): UnshowableRedirectUri[] {
  if (!Array.isArray(redirectUris)) return [];
  const found: UnshowableRedirectUri[] = [];
  for (const uri of redirectUris) {
    if (typeof uri !== 'string') continue;
    const reason = redirectTargetRefusal(uri);
    if (reason !== undefined) found.push({ uri, reason });
  }
  return found;
}

/** What {@link scanUnshowableRedirectUris} reads and when it stops. */
export interface RedirectUriScanSource {
  /** The next page of clients after the row `after` names, by `id`, at most `limit` rows. */
  page(after: string | undefined, limit: number): Promise<RedirectUriScanRow[]>;
  /** Clients per page; {@link REDIRECT_URI_SCAN_PAGE_SIZE} unless given. */
  pageSize?: number;
  /**
   * When to stop, in epoch milliseconds: no page is read once it has passed,
   * and the scan reports `complete: false`. No deadline reads every client.
   */
  deadline?: number;
  /** The clock the deadline is read against; `Date.now` unless given. */
  now?: () => number;
}

/**
 * Read every client, a page at a time, and keep those with a redirect URI the
 * consent screen cannot show, ordered by realm name and then client id.
 */
export async function scanUnshowableRedirectUris(
  source: RedirectUriScanSource
): Promise<UnshowableRedirectUriScan> {
  const pageSize = source.pageSize ?? REDIRECT_URI_SCAN_PAGE_SIZE;
  const now = source.now ?? Date.now;
  const clients: ClientWithUnshowableRedirectUris[] = [];
  let scanned = 0;
  let after: string | undefined;
  let complete = true;
  for (;;) {
    if (source.deadline !== undefined && now() >= source.deadline) {
      complete = false;
      break;
    }
    const rows = await source.page(after, pageSize);
    for (const row of rows) {
      const redirectUris = unshowableRedirectUris(row.redirectUris);
      if (redirectUris.length === 0) continue;
      clients.push({
        id: row.id,
        realmId: row.realmId,
        realmName: row.realmName,
        clientId: row.clientId,
        source: redirectUriSource(row),
        redirectUris,
      });
    }
    scanned += rows.length;
    const last = rows.at(-1);
    if (rows.length < pageSize || last === undefined) break;
    after = last.id;
  }
  clients.sort(
    (a, b) =>
      compareText(a.realmName, b.realmName) ||
      compareText(a.realmId, b.realmId) ||
      compareText(a.clientId, b.clientId)
  );
  return { clients, scanned, complete };
}

/** Code-point order, the same on every machine (no locale). */
function compareText(a: string, b: string): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}
