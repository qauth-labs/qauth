import { z } from 'zod';

import { defineEventType } from '../definition';
import { QAUTH_KEY_EMERGENCY_RETIRED } from '../ssf-mapping';
import { FIRST_RELEASE } from './fields';

/**
 * The realm's keys (ADR-019 Decision 9). A rotation is routine and records no
 * security event; an emergency retirement does, on every event route, so a
 * verifier outside QAuth drops the key before its JWKS cache expires.
 * Emergency retirement itself is #551, which emits this type; #540 defines it
 * and its SSF event first, so the event exists before the operation does.
 */

export const keyEmergencyRetired = defineEventType({
  name: 'key.emergency_retired',
  version: 1,
  rc: 0,
  description:
    'An operator retired a key of the realm that may be compromised (ADR-019 Decision 9): it left the JWKS at once, no verifier in the auth server accepts it, and a new key took its place.',
  category: 'admin',
  severity: 'critical',
  since: FIRST_RELEASE,
  data: z.strictObject({
    keyId: z
      .string()
      .min(1)
      .max(255)
      .describe('The `kid` of the retired key. Never the key itself.'),
    purpose: z
      .string()
      .min(1)
      .max(64)
      .regex(/^[a-z][a-z0-9_]*$/)
      .describe('What the key was for, such as `token_signing` or `event_signing`.'),
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

export const KEY_EVENT_TYPES = [keyEmergencyRetired] as const;
