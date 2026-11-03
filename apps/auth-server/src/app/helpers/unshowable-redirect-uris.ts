import type { FastifyBaseLogger, FastifyInstance } from 'fastify';

/**
 * The boot's warning about clients whose redirect URIs the consent screen
 * cannot show (#914).
 *
 * Since #593 the consent screen always says where the authorization code
 * goes, and refuses a redirect URI it cannot describe (`redirectTarget` in
 * shared-validation) with `invalid_request`; every registration path refuses
 * one too. A client stored before that with such a URI breaks after the
 * upgrade with nothing said: a CIMD client at its document's next fetch, a
 * seed manifest that names it is refused whole, and any other client's new
 * users meet the 400. So each boot names them, once per client, with the
 * command that lists them all and says how to replace each URI.
 *
 * The scan stops after {@link UNSHOWABLE_REDIRECT_URI_SCAN_BUDGET_MS}, so a
 * large client table never holds the boot (Fastify bounds an `onReady` hook
 * at 10 s), and then says the list is incomplete. It never refuses the boot:
 * a failed scan is logged and the server serves on.
 */

/** The command that lists every such client, with the fix for each. */
export const UNSHOWABLE_REDIRECT_URI_COMMAND =
  'pnpm nx run infra-db:db:list-unshowable-redirect-uris';

/** How long the boot spends reading clients. */
export const UNSHOWABLE_REDIRECT_URI_SCAN_BUDGET_MS = 2_000;

/** How many clients the boot names one by one; the rest are counted. */
export const UNSHOWABLE_REDIRECT_URI_CLIENTS_NAMED = 20;

/** What {@link logUnshowableRedirectUris} reads through. */
export interface UnshowableRedirectUriWarningDependencies {
  readonly clients: Pick<
    FastifyInstance['repositories']['oauthClients'],
    'findUnshowableRedirectUris'
  >;
  readonly log: Pick<FastifyBaseLogger, 'warn'>;
  /** The clock the scan's deadline is set from; `Date.now` unless given. */
  readonly now?: () => number;
}

/**
 * Logged for each client the boot names. The client id and realm name are
 * quoted as JSON strings: a row stored before #593 may carry control
 * characters, which a log read in a terminal must not receive raw.
 */
export function unshowableRedirectUriWarning(realmName: string, clientId: string): string {
  return (
    `the client ${JSON.stringify(clientId)} of the realm ${JSON.stringify(realmName)} has a redirect URI the consent screen cannot show, ` +
    `which the screen refuses with invalid_request (#593); \`${UNSHOWABLE_REDIRECT_URI_COMMAND}\` lists every such client and how to replace its URIs`
  );
}

/** Name every client with a redirect URI the consent screen cannot show, as warnings. */
export async function logUnshowableRedirectUris(
  deps: UnshowableRedirectUriWarningDependencies
): Promise<void> {
  const now = deps.now ?? Date.now;
  let scan;
  try {
    scan = await deps.clients.findUnshowableRedirectUris({
      deadline: now() + UNSHOWABLE_REDIRECT_URI_SCAN_BUDGET_MS,
    });
  } catch (error) {
    deps.log.warn(
      { error: error instanceof Error ? error.name : 'unknown' },
      `could not check the clients' redirect URIs at boot; \`${UNSHOWABLE_REDIRECT_URI_COMMAND}\` lists the clients with one the consent screen cannot show`
    );
    return;
  }

  const named = scan.clients.slice(0, UNSHOWABLE_REDIRECT_URI_CLIENTS_NAMED);
  for (const client of named) {
    deps.log.warn(
      {
        realm: client.realmName,
        realmId: client.realmId,
        clientId: client.clientId,
        registration: client.source,
        redirectUris: client.redirectUris,
      },
      unshowableRedirectUriWarning(client.realmName, client.clientId)
    );
  }
  const more = scan.clients.length - named.length;
  if (more > 0) {
    deps.log.warn(
      { clients: scan.clients.length, named: named.length },
      `${more} more ${more === 1 ? 'client has' : 'clients have'} a redirect URI the consent screen cannot show; \`${UNSHOWABLE_REDIRECT_URI_COMMAND}\` lists them all`
    );
  }
  if (!scan.complete) {
    deps.log.warn(
      { scanned: scan.scanned, budgetMs: UNSHOWABLE_REDIRECT_URI_SCAN_BUDGET_MS },
      `the boot's check of the clients' redirect URIs stopped after ${scan.scanned} clients; \`${UNSHOWABLE_REDIRECT_URI_COMMAND}\` checks every client`
    );
  }
}
