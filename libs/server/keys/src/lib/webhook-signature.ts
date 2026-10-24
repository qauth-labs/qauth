/**
 * The Standard Webhooks signature scheme (https://www.standardwebhooks.com/,
 * issue #547), symmetric form: HMAC-SHA256 over `msg_id.timestamp.payload`.
 *
 * The signer computes the signatures (`signWebhook`); the key factory hands
 * the secret out once, in the serialization the specification gives it.
 */

/** The prefix of a symmetric Standard Webhooks secret, as a subscriber receives it. */
export const WEBHOOK_SECRET_PREFIX = 'whsec_';

/** The version identifier of a symmetric Standard Webhooks signature. */
export const WEBHOOK_SIGNATURE_VERSION = 'v1';

/** The longest `webhook-id` the signer signs. */
export const MAX_WEBHOOK_ID_LENGTH = 255;

/** The secret as a subscriber receives it: `whsec_` and the base64 of its bytes. */
export function formatWebhookSecret(secret: Uint8Array): string {
  return WEBHOOK_SECRET_PREFIX + Buffer.from(secret).toString('base64');
}

/**
 * The bytes a signature covers: the message id, the timestamp in seconds and
 * the body, joined by full stops. The body is taken as the exact bytes that
 * are sent, so a receiver that verifies the raw body verifies these bytes.
 */
export function webhookSignedContent(id: string, timestamp: number, body: Uint8Array): Buffer {
  return Buffer.concat([Buffer.from(`${id}.${timestamp}.`, 'utf8'), body]);
}

/** One signature of the `webhook-signature` header: `v1,` and the base64 of the MAC. */
export function formatWebhookSignature(mac: ArrayBuffer): string {
  return `${WEBHOOK_SIGNATURE_VERSION},${Buffer.from(mac).toString('base64')}`;
}

/**
 * Whether `id` can be a `webhook-id`: printable ASCII without a full stop or a
 * space, at most {@link MAX_WEBHOOK_ID_LENGTH} characters. The specification
 * asks that the id never contain `.`, which would make the signed content
 * ambiguous; the rest keeps it a valid header value.
 */
export function isWebhookId(id: unknown): id is string {
  return (
    typeof id === 'string' &&
    id.length > 0 &&
    id.length <= MAX_WEBHOOK_ID_LENGTH &&
    /^[\x21-\x2d\x2f-\x7e]+$/.test(id)
  );
}

/** Whether `timestamp` can be a `webhook-timestamp`: whole seconds since the epoch. */
export function isWebhookTimestamp(timestamp: unknown): timestamp is number {
  return typeof timestamp === 'number' && Number.isSafeInteger(timestamp) && timestamp >= 0;
}
