import type { SignatureAlgorithm } from '@qauth-labs/core-crypto';
import type { DbClient } from '@qauth-labs/infra-db';
import { createKeyFactory, type KekProvider } from '@qauth-labs/server-keys/custody';

import { createRepositoryKeyStore } from './repository-key-stores';

/**
 * THE SIGNING SECRETS OF A WEBHOOK SUBSCRIPTION, as the admin API manages
 * them (ADR-019 Decision 9, issue #537): generate a subscription's first
 * secret, rotate it with an overlap, end the overlap, and delete them all
 * with the subscription.
 *
 * Each secret is the realm's `webhook_signing` key scoped to the
 * subscription: a 32-byte HMAC-SHA256 secret, generated here, in the
 * signer's wiring, and sealed under the KEK. It is handed out once, in the
 * Standard Webhooks form (`whsec_` and base64), by the call that generates
 * it; nothing here returns it again, and the signer only signs with it
 * (`signWebhook`), so the delivery role never holds it.
 *
 * A rotation makes the new secret the subscription's `next` key, which the
 * signer signs with beside the `active` one: every message carries both
 * signatures, so a receiver that knows either verifies it, until the
 * overlap ends and the new secret becomes the only one ({@link
 * WebhookSecrets.endOverlap}). The subscription row stores when that is;
 * the signer role's job ends each overlap whose time has come. The overlap
 * is the subscription's own, so the factory waits for no window of its own
 * (`prepublishMs: 0`).
 */

/** The purpose every key here belongs to. */
const PURPOSE = 'webhook_signing';

/** A secret, as the call that generates it answers it: the only time it appears. */
export interface GeneratedWebhookSecret {
  /** The new secret's `kid`: the subscription's `secret_ref`. */
  readonly kid: string;
  /** The secret, `whsec_` and the base64 of its 32 bytes. */
  readonly secret: string;
}

/** Which subscription a call acts on. */
export interface WebhookSecretScope {
  readonly realmId: string;
  /** The subscription's id: the keys' scope. */
  readonly subscriptionId: string;
  /** An outer transaction to run in, such as the admin call's: the keys commit with it. */
  readonly tx?: DbClient;
}

/** Input of {@link WebhookSecrets.rotate}. */
export interface RotateWebhookSecretInput extends WebhookSecretScope {
  /**
   * Whether the replaced secret keeps signing beside the new one until
   * {@link WebhookSecrets.endOverlap}. `false`: the new secret replaces it
   * at once, as after a leak.
   */
  readonly overlap: boolean;
}

/** What a rotation did, beside the new secret. */
export interface RotatedWebhookSecret extends GeneratedWebhookSecret {
  /**
   * The `kid`s that stopped signing in this call: a rotation that ran
   * while an earlier overlap was still open ends that overlap first, and one
   * without an overlap retires the active secret.
   */
  readonly retiredKids: readonly string[];
}

/** A subscription's signing secrets, managed through the signer's KEK. See the module comment. */
export interface WebhookSecrets {
  /**
   * Generate the subscription's first secret, as its `active` key, under the
   * realm's key lock.
   *
   * @throws as `KeyFactory.createKey`: `ActiveKeyConflictError` when the
   *   subscription already has one, `KeyCreationRefusedError` for a
   *   malformed realm or subscription id
   */
  create(input: WebhookSecretScope): Promise<GeneratedWebhookSecret>;
  /**
   * Generate a new secret for the subscription, under the realm's key lock.
   * A `next` secret an earlier rotation left is made `active` first, so at
   * most two secrets ever sign. With `overlap`, the new secret is the
   * subscription's `next` key and signs beside the active one; without, it
   * becomes the active one at once and the old one is retired.
   */
  rotate(input: RotateWebhookSecretInput): Promise<RotatedWebhookSecret>;
  /**
   * End the subscription's overlap: its `next` secret becomes the active
   * one, and the secret it replaced stops signing. Answers the retired
   * `kid`, or `null` when there was no overlap to end.
   */
  endOverlap(input: WebhookSecretScope): Promise<{ readonly retiredKid: string | null } | null>;
  /** Delete every secret of the subscription, whatever its status. Answers the deleted `kid`s. */
  delete(input: WebhookSecretScope): Promise<readonly string[]>;
}

/** What {@link createWebhookSecrets} works with. */
export interface WebhookSecretsDependencies {
  readonly db: DbClient;
  readonly kekProvider: KekProvider;
  readonly enabledSignatureAlgorithms: readonly SignatureAlgorithm[];
  readonly hybridSigning: boolean;
}

/** A created key's secret, which a `webhook_signing` key always comes with. */
function secretOf(created: { readonly kid: string; readonly secret?: string } | undefined) {
  if (created?.secret === undefined) {
    throw new Error('The key factory created a webhook secret without handing it out');
  }
  return { kid: created.kid, secret: created.secret };
}

/** The webhook secrets over the database and the signer's KEK. */
export function createWebhookSecrets(deps: WebhookSecretsDependencies): WebhookSecrets {
  const store = createRepositoryKeyStore(deps.db);
  const factory = createKeyFactory({
    store,
    kekProvider: deps.kekProvider,
    enabledSignatureAlgorithms: deps.enabledSignatureAlgorithms,
    hybridSigning: deps.hybridSigning,
    // The subscription row holds the overlap: the factory waits for none.
    prepublishMs: 0,
  });

  /** Whether the subscription has a `next` secret, read under the lock. */
  async function hasNext(realmId: string, subscriptionId: string, tx: DbClient) {
    const next = await store.listByRealm(
      realmId,
      { purpose: PURPOSE, scopeId: subscriptionId, status: 'next' },
      tx
    );
    return next.length > 0;
  }

  return Object.freeze({
    async create(input: WebhookSecretScope): Promise<GeneratedWebhookSecret> {
      return store.transaction(async (tx) => {
        await store.lockRealm(input.realmId, tx);
        const [created] = await factory.createKey({
          realmId: input.realmId,
          purpose: PURPOSE,
          scopeId: input.subscriptionId,
          status: 'active',
          tx,
        });
        return Object.freeze(secretOf(created));
      }, input.tx);
    },

    async rotate(input: RotateWebhookSecretInput): Promise<RotatedWebhookSecret> {
      return store.transaction(async (tx) => {
        await store.lockRealm(input.realmId, tx);
        const scope = {
          realmId: input.realmId,
          purpose: PURPOSE,
          scopeId: input.subscriptionId,
          tx,
        } as const;
        const retiredKids: string[] = [];
        // An overlap still open ends now: its new secret becomes the active one.
        if (await hasNext(input.realmId, input.subscriptionId, tx)) {
          const { retiredKid } = await factory.activateNextKey(scope);
          if (retiredKid !== null) retiredKids.push(retiredKid);
        }
        const [created] = await factory.createKey({ ...scope, status: 'next' });
        const generated = secretOf(created);
        if (!input.overlap) {
          const { retiredKid } = await factory.activateNextKey(scope);
          if (retiredKid !== null) retiredKids.push(retiredKid);
        }
        return Object.freeze({ ...generated, retiredKids: Object.freeze(retiredKids) });
      }, input.tx);
    },

    async endOverlap(input: WebhookSecretScope) {
      return store.transaction(async (tx) => {
        await store.lockRealm(input.realmId, tx);
        if (!(await hasNext(input.realmId, input.subscriptionId, tx))) return null;
        const { retiredKid } = await factory.activateNextKey({
          realmId: input.realmId,
          purpose: PURPOSE,
          scopeId: input.subscriptionId,
          tx,
        });
        return Object.freeze({ retiredKid });
      }, input.tx);
    },

    async delete(input: WebhookSecretScope): Promise<readonly string[]> {
      return store.transaction(async (tx) => {
        await store.lockRealm(input.realmId, tx);
        return factory.deleteScopedKeys({
          realmId: input.realmId,
          purpose: PURPOSE,
          scopeId: input.subscriptionId,
          tx,
        });
      }, input.tx);
    },
  } satisfies WebhookSecrets);
}
