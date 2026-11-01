import type { RealmMailRead, RealmMailSource } from '@qauth-labs/fastify-plugin-email';
import {
  mailTransportGaps,
  PolicyValidationError,
  type RealmPolicySnapshot,
  type RealmPolicyStoreOfRealms,
  type RealmSecretCipher,
  realmSecretPaths,
  type RealmSecretStoreOfRealms,
} from '@qauth-labs/fastify-plugin-realm-policy';
import type { FastifyBaseLogger, FastifyInstance } from 'fastify';

/**
 * The realms' secret policy values in the auth server (ADR-019 Decisions 9
 * and 10, issue #529): the SMTP password and the Resend API key of each
 * realm's mail transport.
 *
 * - They are stored encrypted with the realm's `data_at_rest` key, through
 *   the signer ({@link realmSecretCipher}), in `realm_secrets`, and written
 *   only through a policy update or the boot's seed.
 * - The environment seeds them once, at the first boot that can encrypt
 *   them, in the default realm and in each realm whose stored transport is
 *   the environment's and needs them ({@link seedRealmSecrets}).
 * - Only the realm's mail sender reads a value ({@link realmMailSource}).
 */

/**
 * The secret store's cipher over the signer (#529).
 *
 * - Encrypting runs where the signer runs: the boot's seed, in the signer's
 *   process, and the policy update while the admin API runs in that process
 *   too (a single deployment). It calls as `local`, the caller inside the
 *   signer's own process; the admin role gets a grant of its own when it
 *   moves out (#497).
 * - Decrypting is for the mail sender, which the `api` role runs; it calls as
 *   `api`. A process without the signer refuses both (503) until it can call
 *   the signer service.
 *
 * `fastify.signer` is read on each call: the signer plugin registers after the
 * policy store that holds this cipher.
 */
export function realmSecretCipher(fastify: Pick<FastifyInstance, 'signer'>): RealmSecretCipher {
  const cipher: RealmSecretCipher = {
    encrypt: ({ realmId, plaintext, context }) =>
      fastify.signer.encrypt('local', {
        realmId,
        plaintext: Buffer.from(plaintext, 'utf8'),
        context,
      }),
    async decrypt({ realmId, ciphertext, context }) {
      return (await fastify.signer.decrypt('api', { realmId, ciphertext, context })).toString(
        'utf8'
      );
    },
  };
  return Object.freeze(cipher);
}

/** What {@link seedRealmSecrets} reads. */
export interface RealmSecretSeedSettings {
  /** `DEFAULT_REALM_NAME`. */
  readonly realmName: string;
  /** The secret values the environment sets, by policy path (`secretSeedsFromEnv`). */
  readonly seeds: ReadonlyMap<string, string>;
  /** The environment key of each secret path (`mail.smtp.password` → `SMTP_PASSWORD`). */
  readonly seedKeys: ReadonlyMap<string, string>;
  /**
   * The smtp server the environment names (`SMTP_HOST`, `SMTP_PORT`,
   * `SMTP_USER`, as `defaultsFromEnv` reads them): `SMTP_PASSWORD` is the
   * password of this server and user, and goes to no realm that stores
   * another.
   */
  readonly environmentSmtp: SmtpServer;
}

/** The smtp server and user a password belongs to. */
export interface SmtpServer {
  readonly host: string | null;
  readonly port: number | null;
  readonly user: string | null;
}

/** What {@link seedRealmSecrets} works through. */
export interface RealmSecretSeedDependencies {
  readonly realms: Pick<FastifyInstance['repositories']['realms'], 'listPolicyRecords'>;
  readonly policies: Pick<RealmPolicyStoreOfRealms, 'get'>;
  readonly secrets: Pick<RealmSecretStoreOfRealms, 'seed' | 'isSet'>;
  readonly log: Pick<FastifyBaseLogger, 'info' | 'warn' | 'error'>;
}

/** Logged once per boot for each secret seed key the environment sets after the realm's secret was seeded. */
export function secretSeedKeyIgnoredWarning(key: string, realmName: string, path: string): string {
  return `${key} only seeds the first realm's ${path} at its first boot, and is ignored: the realm "${realmName}" keeps its stored ${path}. To replace it, see "Mail secrets move into the realm" on operate/upgrades; remove ${key} from the environment once no node of an earlier release runs`;
}

/**
 * Logged once per boot for each thing the default realm's stored mail
 * transport lacks (#529): the boot no longer refuses such a configuration,
 * which the policy update does, so it says why the realm's mail fails.
 */
export function mailTransportIncompleteWarning(
  realmName: string,
  path: string,
  issue: string
): string {
  return `the realm "${realmName}" cannot send mail: its ${path} ${issue}, so each of its mails fails until a policy update sets it`;
}

/**
 * Logged once per boot for a realm whose stored smtp server or user is not
 * the environment's (review of #937): `SMTP_PASSWORD` belongs to another
 * server, so it is not stored, where it would reach the realm's server.
 */
export function smtpPasswordForAnotherServerError(key: string, realmName: string): string {
  return `${key} is not stored in the realm "${realmName}": the realm's mail.smtp.host, port or user is not SMTP_HOST, SMTP_PORT or SMTP_USER, and the password would go to a server it was not given for. Set the realm's password through a policy update, or make the environment name the realm's server`;
}

/** Logged when a realm other than the default one cannot be seeded this boot; the next boot tries again. */
export function realmSecretSeedFailedWarning(realmName: string): string {
  return `the realm "${realmName}" was not given the environment's mail secret at this boot (it may have no data-at-rest key yet); the next boot tries again`;
}

/** Whether a realm's stored smtp server and user are those the environment names. */
function sameSmtpServer(stored: SmtpServer, environment: SmtpServer): boolean {
  return (
    stored.host === environment.host &&
    stored.port === environment.port &&
    stored.user === environment.user
  );
}

/**
 * The boot step that seeds the realms' secrets (#529), after the key boot
 * step gave the default realm its `data_at_rest` key. A secret that has a
 * row is never written again, so a later change of the environment changes
 * no realm's stored secret (ADR-019 Decision 10).
 *
 * - The default realm: each secret it has no row for gets the environment's
 *   value (`SMTP_PASSWORD`, `RESEND_API_KEY`), or a row that holds none when
 *   the environment does not set it, unless its stored transport needs it:
 *   then it stays without a row, so a later boot that sets it stores it.
 * - Every other realm with policies (one the first boot after the upgrade
 *   filled from the environment, or one created since with its seeds) gets
 *   the environment's value of a secret its stored transport needs and has
 *   no row for, and nothing else: no row records an unset secret there.
 *   Failing (a realm with no data-at-rest key yet) is logged, and the next
 *   boot tries again.
 * - `SMTP_PASSWORD` goes to no realm whose stored `mail.smtp.host`, `port` or
 *   `user` is not the environment's: it is logged as an error instead.
 *
 * Of two nodes that seed together, the first write wins. A realm whose
 * stored policies this release refuses is logged and skipped, never a reason
 * to stop the boot.
 *
 * It logs, never a value: one line per seeded secret; a warning per seed key
 * the environment still sets for a secret the default realm already has; and
 * a warning for each thing the default realm's stored transport lacks (a
 * host, a port, a user, a sender address or its secret), by the policy
 * update's own rule, since the boot no longer refuses such a configuration.
 */
export async function seedRealmSecrets(
  deps: RealmSecretSeedDependencies,
  settings: RealmSecretSeedSettings
): Promise<void> {
  for (const record of await deps.realms.listPolicyRecords()) {
    const realm = { id: record.realmId, name: record.realmName };
    const isDefault = realm.name === settings.realmName;
    let snapshot: RealmPolicySnapshot | undefined;
    try {
      snapshot = await deps.policies.get(realm.id);
    } catch (error) {
      if (!(error instanceof PolicyValidationError)) throw error;
      // Its own boot step names the realm's refused values; the secrets wait.
      deps.log.warn(
        { realm: realm.name, realmId: realm.id, paths: error.issues.map((issue) => issue.path) },
        `the realm "${realm.name}" holds policies this release refuses: its secrets are not seeded until they are fixed`
      );
      continue;
    }
    // A realm with no policies yet sends with the environment's secrets
    // (`realmMailSource`) until a node of this release fills it.
    if (snapshot === undefined || !snapshot.hasPolicies) continue;
    try {
      await seedRealm(deps, settings, realm, snapshot, isDefault);
    } catch (error) {
      if (isDefault) throw error;
      deps.log.warn(
        {
          realm: realm.name,
          realmId: realm.id,
          error: error instanceof Error ? error.name : typeof error,
        },
        realmSecretSeedFailedWarning(realm.name)
      );
    }
  }
}

async function seedRealm(
  deps: RealmSecretSeedDependencies,
  settings: RealmSecretSeedSettings,
  realm: { readonly id: string; readonly name: string },
  snapshot: RealmPolicySnapshot,
  isDefault: boolean
): Promise<void> {
  const { policies } = snapshot;
  // The secrets the stored transport needs, by the policy update's own rule.
  const needed = new Set(
    mailTransportGaps(policies, () => false)
      .map((issue) => issue.path)
      .filter((path) => settings.seedKeys.has(path))
  );
  const smtpMatches = sameSmtpServer(policies.mail.smtp, settings.environmentSmtp);
  const seeds = new Map<string, string>();
  const forAnotherServer: string[] = [];
  for (const [path, value] of settings.seeds) {
    if (!isDefault && !needed.has(path)) continue;
    if (path === 'mail.smtp.password' && !smtpMatches) {
      forAnotherServer.push(path);
      continue;
    }
    seeds.set(path, value);
  }
  const leaveWithoutRow = new Set(isDefault ? needed : settings.seedKeys.keys());
  for (const path of forAnotherServer) leaveWithoutRow.add(path);
  const report = await deps.secrets.seed(realm.id, seeds, { leaveWithoutRow });

  for (const path of report.seeded) {
    deps.log.info(
      { realm: realm.name, realmId: realm.id, policy: path, variable: settings.seedKeys.get(path) },
      'realm secret seeded from the environment: the realm stores it encrypted from now on'
    );
  }
  for (const path of forAnotherServer) {
    // Named where the realm's transport needs it, and so cannot send.
    if (!needed.has(path) || !report.leftWithoutRow.includes(path)) continue;
    const key = settings.seedKeys.get(path) ?? path;
    deps.log.error(
      { variable: key, realm: realm.name, realmId: realm.id, policy: path },
      smtpPasswordForAnotherServerError(key, realm.name)
    );
  }
  if (!isDefault) return;

  for (const path of report.present) {
    const key = settings.seedKeys.get(path);
    if (key === undefined || !settings.seeds.has(path)) continue;
    deps.log.warn(
      { variable: key, realm: realm.name, policy: path },
      secretSeedKeyIgnoredWarning(key, realm.name, path)
    );
  }

  // The policy update's own rule, over what the realm stores now.
  const set = new Set<string>();
  for (const path of realmSecretPaths()) {
    if (await deps.secrets.isSet(realm.id, path)) set.add(path);
  }
  for (const issue of mailTransportGaps(policies, (path) => set.has(path))) {
    deps.log.warn(
      { realm: realm.name, realmId: realm.id, policy: issue.path },
      mailTransportIncompleteWarning(realm.name, issue.path, issue.message)
    );
  }
}

/**
 * Where each realm's mail sender reads its transport (#529): the realm's
 * policies, read anew for every mail (`policyStore.get`, one query), so a
 * change reaches the next mail; and its secret from the secret store.
 *
 * A realm with no policies yet (counter 0: one a node of the previous
 * release created during a rolling upgrade, until a node of this release
 * boots again) reads as its fill, the environment's seeds, and takes its
 * secret from the environment as before (`environmentSecrets`).
 */
export function realmMailSource(
  fastify: Pick<FastifyInstance, 'policyStore' | 'realmSecretStore'>,
  environmentSecrets: ReadonlyMap<string, string>
): RealmMailSource {
  return Object.freeze({
    async read(realmId: string): Promise<RealmMailRead | undefined> {
      const snapshot = await fastify.policyStore.get(realmId);
      if (snapshot === undefined) return undefined;
      const { mail } = snapshot.policies;
      return {
        version: snapshot.version,
        mail: {
          provider: mail.provider,
          fromAddress: mail.fromAddress,
          fromName: mail.fromName,
          smtp: {
            host: mail.smtp.host,
            port: mail.smtp.port,
            secure: mail.smtp.secure,
            user: mail.smtp.user,
          },
        },
        async secretOf(path) {
          if (!snapshot.hasPolicies) return environmentSecrets.get(path);
          return (await fastify.realmSecretStore?.getForUse(realmId, path)) ?? undefined;
        },
      };
    },
  });
}
