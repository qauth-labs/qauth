import type { DeliverySigner } from '@qauth-labs/server-event-delivery';
import { jwsPurposeOfTyp, type Signer } from '@qauth-labs/server-keys';

/**
 * The signer handle of the delivery role (ADR-019 Decision 9, issue #460).
 *
 * Every call goes to the signer as the `delivery` caller, whose grant in
 * `SIGNER_POLICY` is webhook signatures, Security Event Tokens, logout tokens
 * and decrypting a destination's stored secret (an SSF receiver's
 * `Authorization` header, #410) and nothing else, so the handle cannot sign
 * an access token or an ID token even in a single deployment, where the signer
 * runs in the same process. A token's type names the key: a SET is signed with
 * the `event_signing` key, a logout token with the `token_signing` key that
 * signs the ID tokens (OpenID Connect Back-Channel Logout 1.0 §2.4, #624). The
 * role gets signatures and plaintexts back, never a key.
 *
 * @param signer - The signer role's signer: `fastify.signer` in-process, or
 *   the remote signer of a distributed deployment.
 */
export function deliverySignerHandle(signer: Signer): DeliverySigner {
  return Object.freeze({
    signWebhook: (request) =>
      signer.signWebhook('delivery', {
        realmId: request.realmId,
        subscriptionId: request.subscriptionId,
        id: request.id,
        timestamp: request.timestamp,
        body: request.body,
      }),
    signEventToken: (request) =>
      signer.signJws('delivery', {
        realmId: request.realmId,
        // A type signJws does not sign falls to event_signing, which refuses it.
        purpose: jwsPurposeOfTyp(request.typ) ?? 'event_signing',
        typ: request.typ,
        claims: request.claims,
      }),
    decrypt: async (request) =>
      new Uint8Array(
        await signer.decrypt('delivery', {
          realmId: request.realmId,
          ciphertext: request.ciphertext,
          context: request.context,
        })
      ),
  } satisfies DeliverySigner);
}
