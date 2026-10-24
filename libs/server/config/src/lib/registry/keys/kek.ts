import { defineKeys } from '../types';

/**
 * The key-encryption key (KEK) provider (ADR-019 Decision 9): the keys of
 * `kekEnvSchema`. ADR-018 §5 puts the KEK provider in the stable subset.
 */
export const KEK_KEYS = defineKeys([
  {
    name: 'KEK_PROVIDER',
    tier: 'stable',
    role: 'deployment',
    owner: 'key-custody',
    default: 'local',
    since: '0.2.0',
    docs: 'Which provider holds the key-encryption key (KEK) that wraps every stored key: `local` reads it from `KEK` or `KEK_PATH`, and any other name loads the optional package `@qauth-labs/keys-<name>`.',
  },
  {
    name: 'KEK',
    tier: 'stable',
    role: 'deployment',
    owner: 'key-custody',
    default: {
      computed:
        'a published development KEK outside production; refused when `NODE_ENV=production`',
    },
    since: '0.2.0',
    secret: true,
    docs: 'The KEK of the `local` provider, as the base64 of 32 random bytes, for example from `openssl rand -base64 32`; the boot stops when a key variable must be imported into the key store and no KEK is set.',
  },
  {
    name: 'KEK_PATH',
    tier: 'stable',
    role: 'deployment',
    owner: 'key-custody',
    default: null,
    since: '0.2.0',
    docs: 'A file holding the KEK as base64; it takes precedence over `KEK`, and the server warns when group or others can read or write it.',
  },
  {
    name: 'KEK_PREVIOUS',
    tier: 'stable',
    role: 'deployment',
    owner: 'key-custody',
    default: null,
    since: '0.2.0',
    secret: true,
    docs: 'The KEK in use before a KEK rotation, as base64; keys wrapped under it still open until they are re-wrapped.',
  },
  {
    name: 'KEK_PREVIOUS_PATH',
    tier: 'stable',
    role: 'deployment',
    owner: 'key-custody',
    default: null,
    since: '0.2.0',
    docs: 'A file holding the previous KEK as base64; it takes precedence over `KEK_PREVIOUS`.',
  },
]);
