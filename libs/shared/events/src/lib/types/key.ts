import { z } from 'zod';

import { defineEventType } from '../definition';
import { extensibleEnum } from '../envelope';
import { QAUTH_KEY_EMERGENCY_RETIRED } from '../ssf-mapping';
import { FIRST_RELEASE } from './fields';

/**
 * The realm's keys (ADR-019 Decision 9). A rotation is routine and records no
 * security event; an emergency retirement does, on every event route, so a
 * verifier outside QAuth drops the key before its JWKS cache expires.
 * Emergency retirement itself is #551, which emits this type; #540 defines it
 * and its SSF event first, so the event exists before the operation does.
 *
 * The scheduled rotation (#542) records each of its steps as an admin event,
 * in the step's transaction: the realm's audit trail shows when each key was
 * created, switched to and retired, by QAuth itself (actor `system`).
 */

/**
 * The key purposes whose public keys QAuth publishes (`published` in
 * `@qauth-labs/server-keys`' purpose table): the keys a verifier outside
 * QAuth may hold. Retiring a key nobody outside sees, such as the
 * data-at-rest key, is no event a receiver can act on, and naming it would
 * tell every receiver of the realm about QAuth's internal keys.
 */
export const PUBLISHED_KEY_PURPOSES = [
  'token_signing',
  'event_signing',
  'federation_entity',
  'trust_anchor',
  'oid4vp_request_signing',
  'oid4vp_response_encryption',
  'upstream_client_assertion',
] as const;

export const keyEmergencyRetired = defineEventType({
  name: 'key.emergency_retired',
  version: 1,
  rc: 0,
  description:
    'An operator retired a published key of the realm that may be compromised (ADR-019 Decision 9): it left the JWKS at once, no verifier in the auth server accepts it, and a new key took its place. A key QAuth does not publish, such as the data-at-rest key, is not recorded as this type.',
  category: 'admin',
  severity: 'critical',
  since: FIRST_RELEASE,
  data: z.strictObject({
    keyId: z
      .string()
      .min(1)
      .max(255)
      .describe('The `kid` of the retired key. Never the key itself.'),
    purpose: extensibleEnum(PUBLISHED_KEY_PURPOSES).describe(
      'What the key was for, one of the purposes whose keys QAuth publishes, such as `token_signing` or `event_signing`. The set may grow in a minor release.'
    ),
  }),
  security: true,
  ssf: {
    event: QAUTH_KEY_EMERGENCY_RETIRED,
    subject: 'key',
    members: { kid: { data: 'keyId' }, purpose: { data: 'purpose' } },
  },
  ssfNote:
    'Defined ahead of emergency retirement itself (#551), which emits it; nothing emits it before then.',
});

/**
 * The purposes whose keys the scheduled rotation replaces (`rotation: automatic`
 * and not scoped in `@qauth-labs/server-keys`' purpose table): published ones
 * and the ones QAuth keeps to itself alike, as an admin event goes to the
 * realm's audit trail and not to a security event receiver.
 */
export const ROTATING_KEY_PURPOSES = [
  'token_signing',
  'event_signing',
  'oid4vp_response_encryption',
  'data_at_rest',
  'cookie_hmac',
  'agent_wrap',
] as const;

/** The algorithms a rotating key may have (`KEY_ALGORITHMS` in `@qauth-labs/server-keys`). */
export const ROTATING_KEY_ALGORITHMS = [
  'EdDSA',
  'RS256',
  'ML-DSA-65',
  'ECDH-ES',
  'A256GCM',
  'HS256',
] as const;

/** The most keys one rotation step names: a hybrid pair and the keys beside it. */
const ROTATION_KEYS_MAX = 4;

const rotatedKeySchema = z
  .strictObject({
    keyId: z.string().min(1).max(255).describe('The `kid` of the key. Never the key itself.'),
    algorithm: extensibleEnum(ROTATING_KEY_ALGORITHMS).describe(
      "The key's algorithm, such as `EdDSA`, or `ML-DSA-65` for the second key of a hybrid pair. The set may grow in a minor release."
    ),
  })
  .describe('One key of the step.');

const rotatingPurposeSchema = extensibleEnum(ROTATING_KEY_PURPOSES).describe(
  'What the keys are for, one of the purposes the rotation replaces on a schedule, such as `token_signing` or `cookie_hmac`. The set may grow in a minor release.'
);

export const keyNextCreated = defineEventType({
  name: 'key.next_created',
  version: 1,
  rc: 0,
  description:
    "The scheduled key rotation created the realm's next key for a purpose (ADR-019 Decision 9): a published key is in its JWKS from now on (the realm's, or the SSF transmitter's for an event signing key) but signs nothing yet, and the key it will replace keeps signing. Emitted in the transaction that stores the key.",
  category: 'admin',
  severity: 'info',
  since: 'v0.3.0',
  data: z.strictObject({
    purpose: rotatingPurposeSchema,
    created: z
      .array(rotatedKeySchema)
      .min(1)
      .max(ROTATION_KEYS_MAX)
      .describe('The new keys: one key, or both keys of a hybrid pair.'),
    activatesAt: z.iso
      .datetime()
      .describe(
        'The earliest moment the new keys may sign, as an RFC 3339 time in UTC: once the active key has served its period and the new keys have been published for the pre-publication window, and, for a cookie key, once the cookie key retired before it has left its retention. The switch itself is recorded as `key.rotated`.'
      ),
  }),
});

export const keyRotated = defineEventType({
  name: 'key.rotated',
  version: 1,
  rc: 0,
  description:
    'The scheduled key rotation switched a purpose of the realm to its next key (ADR-019 Decision 9): from `activatesAt` the new keys sign and the old keys only verify or decrypt, until `retainedUntil`. Emitted in the transaction that writes the switch, which takes effect a little later so every node learns of the new keys first.',
  category: 'admin',
  severity: 'info',
  since: 'v0.3.0',
  data: z.strictObject({
    purpose: rotatingPurposeSchema,
    activated: z
      .array(rotatedKeySchema)
      .min(1)
      .max(ROTATION_KEYS_MAX)
      .describe('The keys that sign from `activatesAt`: one key, or both keys of a hybrid pair.'),
    retired: z
      .array(rotatedKeySchema)
      .min(1)
      .max(ROTATION_KEYS_MAX)
      .describe('The keys that stop signing at `activatesAt`.'),
    activatesAt: z.iso
      .datetime()
      .describe(
        'When the new keys start to sign and the old ones stop, as an RFC 3339 time in UTC.'
      ),
    retainedUntil: z.iso
      .datetime()
      .optional()
      .describe(
        'When the retired keys leave the JWKS and the verification set, or stop verifying cookies or decrypting stored data, as an RFC 3339 time in UTC. Absent when they are kept with no end, as a data-at-rest key is while a ciphertext it sealed may still be stored.'
      ),
  }),
});

export const KEY_EVENT_TYPES = [keyEmergencyRetired, keyNextCreated, keyRotated] as const;
