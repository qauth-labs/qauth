import { defineKeys } from '../types';

/**
 * The delivery role's retry schedule (ADR-019 Decision 8, issue #460): the
 * keys of `eventDeliveryEnvSchema`.
 *
 * `advanced` while the delivery role is new and has no route yet: webhooks
 * (#538) and SSF streams (#410) may want to tune it.
 */
export const EVENT_DELIVERY_KEYS = defineKeys([
  {
    name: 'EVENT_DELIVERY_MAX_ATTEMPTS',
    tier: 'advanced',
    role: 'deployment',
    owner: 'events',
    default: '12',
    since: '0.2.0',
    docs: 'The attempts an event delivery to a webhook or another route gets before it ends `failed`; a failed delivery stays in the delivery history.',
  },
  {
    name: 'EVENT_DELIVERY_RETRY_INITIAL_DELAY',
    tier: 'advanced',
    role: 'deployment',
    owner: 'events',
    default: '30',
    since: '0.2.0',
    docs: 'Seconds an event delivery waits after its first failed attempt; each later wait doubles, less up to 20% at random.',
  },
  {
    name: 'EVENT_DELIVERY_RETRY_MAX_DELAY',
    tier: 'advanced',
    role: 'deployment',
    owner: 'events',
    default: '21600',
    since: '0.2.0',
    docs: 'The longest wait between two attempts of an event delivery, in seconds; at least `EVENT_DELIVERY_RETRY_INITIAL_DELAY`.',
  },
]);
