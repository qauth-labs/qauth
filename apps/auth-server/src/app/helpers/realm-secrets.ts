import type { RealmMailRead, RealmMailSource } from '@qauth-labs/fastify-plugin-email';
import type {
  RealmPolicyStoreOfRealms,
  RealmSecretCipher,
  RealmSecretStoreOfRealms,
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
 * - The environment seeds them once, for the default realm, at the first boot
 *   that can encrypt them ({@link seedDefaultRealmSecrets}).
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

/** What {@link seedDefaultRealmSecrets} reads. */
export interface DefaultRealmSecretSeedSettings {
  /** `DEFAULT_REALM_NAME`. */
  readonly realmName: string;
  /** The secret values the environment sets, by policy path (`secretSeedsFromEnv`). */
  readonly seeds: ReadonlyMap<string, string>;
  /** The environment key of each secret path (`mail.smtp.password` → `SMTP_PASSWORD`). */
  readonly seedKeys: ReadonlyMap<string, string>;
}

/** What {@link seedDefaultRealmSecrets} works through. */
export interface DefaultRealmSecretSeedDependencies {
  readonly realms: Pick<FastifyInstance['repositories']['realms'], 'findByName'>;
  readonly policies: Pick<RealmPolicyStoreOfRealms, 'ofRealm'>;
  readonly secrets: Pick<RealmSecretStoreOfRealms, 'seed' | 'isSet'>;
  readonly log: Pick<FastifyBaseLogger, 'info' | 'warn'>;
}

/** Logged once per boot for each secret seed key the environment sets after the realm's secret was seeded. */
export function secretSeedKeyIgnoredWarning(key: string, realmName: string, path: string): string {
  return `${key} only seeds the first realm's ${path} at its first boot, and is ignored: the realm "${realmName}" keeps its stored ${path}, which a policy update changes. Remove ${key} from the environment once no node of an earlier release runs`;
}

/** Logged once per boot when the default realm's stored transport lacks its secret. */
export function mailSecretMissingWarning(
  realmName: string,
  provider: string,
  path: string
): string {
  return `the realm "${realmName}" sends mail through ${provider}, but its ${path} is not set: its mail fails until a policy update sets it`;
}

/**
 * The boot step that seeds the default realm's secrets (#529), after the key
 * boot step gave the realm its `data_at_rest` key: each secret the realm has
 * no row for gets the environment's value (`SMTP_PASSWORD`,
 * `RESEND_API_KEY`), or a row that holds none when the environment does not
 * set it. A secret that has a row is never written again, so a later change
 * of the environment changes no realm (ADR-019 Decision 10), and only the
 * first realm is seeded: a realm created later gets its secrets through a
 * policy update.
 *
 * It logs, never a value: one line per seeded secret; a warning per seed key
 * the environment still sets for a secret that was already seeded; and a
 * warning when the realm's stored transport lacks its secret, since the boot
 * no longer refuses such a configuration (the policy update does).
 */
export async function seedDefaultRealmSecrets(
  deps: DefaultRealmSecretSeedDependencies,
  settings: DefaultRealmSecretSeedSettings
): Promise<void> {
  const realm = await deps.realms.findByName(settings.realmName);
  // The default realm's boot step creates the realm before this step runs.
  if (realm === undefined) return;
  const report = await deps.secrets.seed(realm.id, settings.seeds);
  for (const path of report.seeded) {
    deps.log.info(
      {
        realm: realm.name,
        realmId: realm.id,
        policy: path,
        variable: settings.seedKeys.get(path),
      },
      'realm secret seeded from the environment: the realm stores it encrypted from now on'
    );
  }
  for (const path of report.present) {
    const key = settings.seedKeys.get(path);
    if (key === undefined || !settings.seeds.has(path)) continue;
    deps.log.warn(
      { variable: key, realm: realm.name, policy: path },
      secretSeedKeyIgnoredWarning(key, realm.name, path)
    );
  }

  const { provider } = deps.policies.ofRealm(realm).policies.mail;
  const needed =
    provider === 'smtp'
      ? 'mail.smtp.password'
      : provider === 'resend'
        ? 'mail.resend.apiKey'
        : undefined;
  if (needed !== undefined && !(await deps.secrets.isSet(realm.id, needed))) {
    deps.log.warn(
      { realm: realm.name, realmId: realm.id, policy: needed },
      mailSecretMissingWarning(realm.name, provider, needed)
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
