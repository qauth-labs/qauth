/**
 * What `seed-oauth-clients.ts` prints for its `clients` entries. Kept apart
 * from the script, which runs on import, so a test can read the report.
 *
 * The secret block keeps its shape: a line of two spaces and the client id,
 * then `secret:`, `fingerprint:` and `action:`. The wire-suite CI job and
 * `scripts/upgrade-test/upgrade-test.sh` read a client's secret from it.
 */
import { createHash } from 'node:crypto';

import type { Issued, SecretlessMethod } from './seed-clients';

/** A created or rotated entry the run issued a secret for. */
type WithSecret = Issued & { secret: string };

/** A created or rotated entry written without a secret (#1138). */
type Secretless = Issued & { authenticatesWith: SecretlessMethod };

function fingerprint(secret: string): string {
  return createHash('sha256').update(secret).digest('hex').slice(0, 8);
}

/**
 * Print what a run did to its `clients` entries, and set a failing exit code
 * when it refused one. A secret is printed only for an entry that carries
 * one (#1138); an entry written without a secret is named on a line of its
 * own, with its action and its method, after every secret.
 */
export function reportClients(realm: string, issued: readonly Issued[]): void {
  const created = issued.filter((i) => i.action === 'created');
  const rotated = issued.filter((i) => i.action === 'rotated');
  const skipped = issued.filter((i) => i.action === 'skipped');
  const refused = issued.filter((i) => i.action === 'refused');
  const written = [...created, ...rotated];
  const withSecret = written.filter((i): i is WithSecret => i.secret !== undefined);
  const secretless = written.filter((i): i is Secretless => i.authenticatesWith !== undefined);

  console.log(
    `\nSeeded realm "${realm}": ` +
      `${created.length} created, ${rotated.length} rotated, ${skipped.length} skipped.\n`
  );

  if (withSecret.length > 0) {
    console.log(
      'Store these plaintext secrets securely — the DB only keeps argon2id hashes.\n' +
        '  (fingerprint = first 8 chars of sha256(secret), for cross-checking)\n'
    );
    for (const i of withSecret) {
      console.log(`  ${i.clientId}`);
      console.log(`    secret:      ${i.secret}`);
      console.log(`    fingerprint: ${fingerprint(i.secret)}`);
      console.log(`    action:      ${i.action}`);
    }
    console.log('');
  }

  // #1138: a private_key_jwt or public client holds a hash no secret
  // matches, and is named on one line, never as a block of its own: a reader
  // of the secret block that matched its id line would take the next secret.
  if (secretless.length > 0) {
    console.log(
      'No secret for these clients: they authenticate without one, and the DB keeps a hash ' +
        'no secret matches.' +
        (secretless.some((i) => i.action === 'rotated')
          ? ' On a rotated one it replaced the hash of any secret an earlier release printed.'
          : '')
    );
    for (const i of secretless) {
      console.log(
        `  ${i.clientId}: ${i.action}, no secret (authenticates with ${i.authenticatesWith})`
      );
    }
    console.log('');
  }

  const firstParty = issued.filter((i) => i.firstPartyChanged);
  if (firstParty.length > 0) {
    console.log('First-party profile changed (recorded as client.first_party_changed):');
    for (const i of firstParty) {
      console.log(
        `  ${i.clientId}` +
          (i.revokedTokenCount
            ? `: profile removed, ${i.revokedTokenCount} refresh tokens revoked`
            : '')
      );
    }
    console.log('');
  }

  const notFirstParty = refused.filter(
    (r) => r.refusal !== 'client_credentials_scopes_dropped' && r.refusal !== 'service_account'
  );
  if (notFirstParty.length > 0) {
    console.error(
      'Refused, and left unchanged: these entries set first_party_profile on a client that ' +
        'can never be first party (a developer, dynamic registration or a CIMD document wrote it):\n  ' +
        notFirstParty.map((r) => `${r.clientId} (${r.refusal})`).join(', ') +
        '\n'
    );
    process.exitCode = 1;
  }

  // #522: the client is a service account's, which the service-accounts
  // command writes; an entry never rewrites it.
  const serviceAccountClients = refused.filter((r) => r.refusal === 'service_account');
  if (serviceAccountClients.length > 0) {
    console.error(
      "Refused, and left unchanged: these clients are service accounts' clients, which " +
        'authenticate with private_key_jwt and hold no secret. Manage them with ' +
        '`pnpm nx run auth-server:service-accounts`, and remove them from the manifest:\n  ' +
        serviceAccountClients.map((r) => r.clientId).join(', ') +
        '\n'
    );
    process.exitCode = 1;
  }

  // #891: the stored client narrows its client_credentials grant, and the
  // entry would lift that narrowing.
  const scopesDropped = refused.filter((r) => r.refusal === 'client_credentials_scopes_dropped');
  if (scopesDropped.length > 0) {
    console.error(
      'Refused, and left unchanged: these clients limit the scopes client_credentials may issue ' +
        '(client_credentials_scopes), and their entries do not, so --rotate would lift the limit. ' +
        'Add client_credentials_scopes to the entry, or to lift the limit on purpose set the ' +
        'column to NULL first:\n  ' +
        scopesDropped.map((r) => r.clientId).join(', ') +
        '\n'
    );
    process.exitCode = 1;
  }

  if (skipped.length > 0) {
    console.log(
      `Skipped (already exist; pass --rotate to re-issue secrets):\n  ` +
        skipped.map((s) => s.clientId).join(', ') +
        '\n'
    );
  }
}
