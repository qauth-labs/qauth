import { defineKeys } from '../types';

/**
 * The scheduled key rotation (ADR-019 Decision 9, issue #542): the keys of
 * `keyRotationEnvSchema`. Advanced keys: the defaults follow ADR-019, and a
 * deployment changes them only for a reason of its own.
 */
export const KEY_ROTATION_KEYS = defineKeys([
  {
    name: 'KEY_ROTATION_PERIOD_DAYS',
    tier: 'advanced',
    role: 'deployment',
    owner: 'key-custody',
    default: '90',
    since: '0.3.0',
    docs: "The days a realm's signing, cookie and data-at-rest keys serve before the rotation job replaces each with a new key, at least `KEY_PREPUBLISH_DAYS`, which the boot checks.",
  },
  {
    name: 'KEY_PREPUBLISH_DAYS',
    tier: 'advanced',
    role: 'deployment',
    owner: 'key-custody',
    default: '7',
    since: '0.3.0',
    docs: "The days a new key is published in the realm's JWKS, signing nothing, before it replaces the active key, so relying parties fetch it first; a rotation job that was down waits this long again before the switch.",
  },
  {
    name: 'KEY_RETIRED_RETENTION_DAYS',
    tier: 'advanced',
    role: 'deployment',
    owner: 'key-custody',
    default: '14',
    since: '0.3.0',
    docs: 'The days a replaced key stays published and verifying, or keeps verifying cookies and decrypting stored data, at least; the rotation job keeps it longer while a token, cookie or stored value it made may still be in use.',
  },
]);
