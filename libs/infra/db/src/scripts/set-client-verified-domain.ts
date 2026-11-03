/**
 * Set or clear an operator-provisioned client's verified domain without
 * issuing it a new secret (#914).
 *
 * Every screen that names a client leads with its verified domain (ADR-019
 * Decision 6, #593); an operator-provisioned client without one shows as an
 * unverified app. The seed manifest's `verified_domain` reaches an existing
 * client only with `--rotate`, which also rotates its secret. This writes the
 * column alone. A public suffix, a URL, a port, an IP address or a single
 * label is refused, as the manifest refuses it.
 *
 * Usage (from the repo root):
 *
 *   DATABASE_URL=postgresql://qauth:pw@host:5432/qauth \
 *     pnpm nx run infra-db:db:set-client-verified-domain -- \
 *     --realm=<realm name> --client-id=<client_id> (--domain=<domain> | --clear)
 *
 * A later `db:seed-oauth-clients --rotate` writes the manifest entry's
 * `verified_domain` over it (none clears it), so put the domain in the
 * manifest too.
 */
import type { InvalidVerifiedDomainReason } from '@qauth-labs/shared-validation';
import * as dotenv from 'dotenv';
import { drizzle } from 'drizzle-orm/node-postgres';

import {
  parseVerifiedDomainArgs,
  setClientVerifiedDomain,
  VERIFIED_DOMAIN_USAGE,
} from './client-verified-domain';

dotenv.config({ path: '../../../.env' });

/** Why the domain was refused, for each reason `normaliseVerifiedDomain` gives. */
const INVALID_DOMAIN: Readonly<Record<InvalidVerifiedDomainReason, string>> = {
  malformed: 'is not a bare DNS name (no URL, port, path, wildcard, underscore or empty label)',
  ip_literal: 'is an IP address; a verified domain is a DNS name',
  single_label: 'has a single label; a verified domain has a registrable domain',
  too_long: 'is longer than 253 characters',
  public_suffix:
    'is a public suffix (on the Public Suffix List, a shared-hosting suffix included), under which unrelated parties hold names',
};

async function main(): Promise<void> {
  const args = parseVerifiedDomainArgs(process.argv);
  if (!args) {
    console.error(VERIFIED_DOMAIN_USAGE);
    process.exit(2);
  }

  const databaseUrl = process.env['DATABASE_URL'];
  if (!databaseUrl) {
    console.error('DATABASE_URL must be set in the environment.');
    process.exit(2);
  }

  const db = drizzle(databaseUrl);
  const client = JSON.stringify(args.clientId);
  const realm = JSON.stringify(args.realm);
  try {
    const result = await setClientVerifiedDomain(db, args);
    switch (result.status) {
      case 'invalid_domain':
        console.error(
          `The domain ${JSON.stringify(args.domain)} ${INVALID_DOMAIN[result.reason]}. Nothing changed.`
        );
        process.exitCode = 1;
        return;
      case 'realm_not_found':
        console.error(`Realm ${realm} not found.`);
        process.exitCode = 1;
        return;
      case 'client_not_found':
        console.error(`Client ${client} not found in realm ${realm}.`);
        process.exitCode = 1;
        return;
      case 'cimd_client':
        console.error(
          `Client ${client} is a CIMD client: the screens show the host of its client id, which the server fetched its metadata document from. Nothing changed.`
        );
        process.exitCode = 1;
        return;
      case 'not_operator_provisioned':
        console.error(
          `Client ${client} is not operator-provisioned (provisioned_by_operator is false), so no screen would show a verified domain for it. Nothing changed. ` +
            'A dynamically registered or developer-owned client stays unverified; to vouch for it, provision it with db:seed-oauth-clients --rotate.'
        );
        process.exitCode = 1;
        return;
      case 'unchanged':
        console.log(
          result.verifiedDomain === null
            ? `Client ${client} has no verified domain; nothing changed.`
            : `Client ${client} already has the verified domain ${result.verifiedDomain}; nothing changed.`
        );
        return;
      case 'set':
        console.log(
          `Client ${client} now has the verified domain ${result.verifiedDomain}` +
            (result.previous === null ? '.' : ` (was ${result.previous}).`) +
            ' Its secret is unchanged.'
        );
        break;
      case 'cleared':
        console.log(
          `Client ${client} no longer has a verified domain (was ${result.previous}): the screens show it as an unverified app.`
        );
        break;
    }
    console.log(
      'A later db:seed-oauth-clients --rotate writes the manifest entry’s verified_domain over this value, so put it in the manifest too.'
    );
  } finally {
    await db.$client.end();
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? (err.stack ?? err.message) : err);
  process.exit(1);
});
