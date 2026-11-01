import type { InferSelectModel } from 'drizzle-orm';

import type { realmSecrets } from '../lib/schema/realm-secrets';
import type { DbClient } from './database';

/** A `realm_secrets` row (#529): an encrypted value, or a secret that holds none. */
export type RealmSecret = InferSelectModel<typeof realmSecrets>;

/** A secret's value as it is stored: the signer's ciphertext and the `kid` that encrypted it. */
export interface RealmSecretValue {
  /** The signer's `data_at_rest` ciphertext, `v1.<kid>.<iv>.<ciphertext>`. */
  readonly ciphertext: string;
  /** The `kid` the ciphertext names. */
  readonly keyId: string;
}

/**
 * The secret values of each realm's secret policy fields (`realm_secrets`,
 * ADR-019 Decisions 9 and 10, #529). It holds ciphertext only: the realm's
 * secret store encrypts before it writes and decrypts after it reads, through
 * the signer. `null` as a value is a secret that holds none.
 */
export interface RealmSecretsRepository {
  /** The row of the secret `name` of the realm, or `undefined` when it has none. */
  find(realmId: string, name: string, tx?: DbClient): Promise<RealmSecret | undefined>;
  /** Set the secret `name` of the realm to `value`, or to none with `null`, creating its row. */
  write(
    realmId: string,
    name: string,
    value: RealmSecretValue | null,
    tx?: DbClient
  ): Promise<void>;
  /**
   * Create the row of the secret `name` with `value` unless the realm already
   * has one, whatever it holds: the boot's seed from the environment, which
   * the first node to boot writes and every later boot leaves alone.
   *
   * @returns whether this call created the row
   */
  insertIfAbsent(
    realmId: string,
    name: string,
    value: RealmSecretValue | null,
    tx?: DbClient
  ): Promise<boolean>;
}
