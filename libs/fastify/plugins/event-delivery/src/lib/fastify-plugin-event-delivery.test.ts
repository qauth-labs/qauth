import type { Signer } from '@qauth-labs/server-keys';
import { isSignerCallAllowed } from '@qauth-labs/server-keys';
import { Registry } from 'prom-client';
import { describe, expect, it, vi } from 'vitest';

import { DELIVERY_METRIC_NAMES, registerDeliveryMetrics } from './metrics';
import { deliverySignerHandle } from './signer-handle';

describe('deliverySignerHandle', () => {
  function signer() {
    return {
      signWebhook: vi.fn(async () => 'v1,c2ln'),
      signJws: vi.fn(async () => 'h.p.s'),
      decrypt: vi.fn(async () => Buffer.from('Bearer t')),
    };
  }

  it('signs a webhook message as the delivery caller', async () => {
    const fake = signer();
    const handle = deliverySignerHandle(fake as unknown as Signer);
    const body = new TextEncoder().encode('{"id":"x"}');

    expect(
      await handle.signWebhook({ realmId: 'r', subscriptionId: 's', id: 'e', timestamp: 1, body })
    ).toBe('v1,c2ln');
    expect(fake.signWebhook).toHaveBeenCalledWith('delivery', {
      realmId: 'r',
      subscriptionId: 's',
      id: 'e',
      timestamp: 1,
      body,
    });
  });

  it('signs event tokens with event_signing only, as the delivery caller', async () => {
    const fake = signer();
    const handle = deliverySignerHandle(fake as unknown as Signer);
    await handle.signEventToken({ realmId: 'r', typ: 'secevent+jwt', claims: { jti: 'j' } });
    expect(fake.signJws).toHaveBeenCalledWith('delivery', {
      realmId: 'r',
      purpose: 'event_signing',
      typ: 'secevent+jwt',
      claims: { jti: 'j' },
    });
  });

  it('decrypts a stored destination secret as the delivery caller', async () => {
    const fake = signer();
    const handle = deliverySignerHandle(fake as unknown as Signer);
    const plain = await handle.decrypt({ realmId: 'r', ciphertext: 'v1.k.i.c', context: 'ctx' });
    expect(new TextDecoder().decode(plain)).toBe('Bearer t');
    expect(fake.decrypt).toHaveBeenCalledWith('delivery', {
      realmId: 'r',
      ciphertext: 'v1.k.i.c',
      context: 'ctx',
    });
  });

  it('asks for nothing the signer policy refuses the delivery caller', () => {
    expect(isSignerCallAllowed('delivery', 'signWebhook')).toBe(true);
    expect(isSignerCallAllowed('delivery', 'signJws', 'event_signing')).toBe(true);
    expect(isSignerCallAllowed('delivery', 'decrypt', 'delivery:ssf_streams.x:1')).toBe(true);
    expect(isSignerCallAllowed('delivery', 'decrypt', 'another_table.secret:1')).toBe(false);
    // What the handle never offers.
    expect(isSignerCallAllowed('delivery', 'signJws', 'token_signing')).toBe(false);
    expect(isSignerCallAllowed('delivery', 'encrypt')).toBe(false);
    expect(Object.keys(deliverySignerHandle(signer() as unknown as Signer)).sort()).toEqual([
      'decrypt',
      'signEventToken',
      'signWebhook',
    ]);
  });
});

describe('registerDeliveryMetrics', () => {
  function setup(store: {
    pendingByKind: () => Promise<Record<string, number>>;
    deliveryLagSeconds: () => Promise<number>;
  }) {
    const registry = new Registry();
    const warn = vi.fn();
    const metrics = registerDeliveryMetrics(registry, {
      store,
      kinds: ['webhook', 'ssf'],
      now: () => 1_000,
      warn,
    });
    return { registry, metrics, warn };
  }

  it('reports pending deliveries per kind, 0 for a kind with none, the lag and the attempts', async () => {
    const { registry, metrics } = setup({
      pendingByKind: async () => ({ webhook: 3, retired: 1 }),
      deliveryLagSeconds: async () => 12.5,
    });
    metrics.attempt('webhook', 'retry');
    metrics.attempt('webhook', 'retry');
    metrics.attempt('webhook', 'failed');
    metrics.attempt('ssf', 'delivered');

    const text = await registry.metrics();
    expect(text).toContain(`${DELIVERY_METRIC_NAMES.pending}{kind="webhook"} 3`);
    expect(text).toContain(`${DELIVERY_METRIC_NAMES.pending}{kind="ssf"} 0`);
    expect(text).toContain(`${DELIVERY_METRIC_NAMES.pending}{kind="retired"} 1`);
    expect(text).toContain(`${DELIVERY_METRIC_NAMES.lag} 12.5`);
    expect(text).toContain(`${DELIVERY_METRIC_NAMES.attempts}{kind="webhook",result="retry"} 2`);
    expect(text).toContain(`${DELIVERY_METRIC_NAMES.attempts}{kind="webhook",result="failed"} 1`);
    expect(text).toContain(`${DELIVERY_METRIC_NAMES.attempts}{kind="ssf",result="delivered"} 1`);
  });

  it('reports NaN when the queue cannot be read, and says so', async () => {
    const { registry, warn } = setup({
      pendingByKind: async () => {
        throw new Error('down');
      },
      deliveryLagSeconds: async () => {
        throw new Error('down');
      },
    });
    const text = await registry.metrics();
    expect(text).toContain(`${DELIVERY_METRIC_NAMES.pending}{kind="webhook"} Nan`);
    expect(text).toContain(`${DELIVERY_METRIC_NAMES.lag} Nan`);
    expect(warn).toHaveBeenCalledTimes(2);
  });
});
