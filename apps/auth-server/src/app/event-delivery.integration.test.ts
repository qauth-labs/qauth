import { randomUUID } from 'node:crypto';

import type { DeliveryRoute } from '@qauth-labs/fastify-plugin-event-delivery';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  resetE2eState,
  startE2eInfrastructure,
} from '../testing/e2e-harness';

/**
 * THE DELIVERY ROLE IN THE AUTH SERVER (ADR-019 Decision 8, issue #460).
 *
 * The real app boots with the delivery role in-process, and a test route whose
 * destination is down. The acceptance criterion: `qauth_events_pending` and
 * the lag gauge appear on `/metrics` and grow while the route is failing. The
 * attempts counter shows the failures by route kind.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const SIGNED_IN = 'urn:qauth:event:user.signed_in:v1-rc.0';

/** One series' value on `/metrics`, or NaN when it is not there. */
async function series(app: FastifyInstance, line: RegExp): Promise<number> {
  const response = await app.inject({ method: 'GET', url: '/metrics' });
  expect(response.statusCode).toBe(200);
  const match = line.exec(response.body);
  return match ? Number(match[1]) : Number.NaN;
}

const pending = (app: FastifyInstance) =>
  series(app, /^qauth_events_pending\{kind="test",app="auth-server"\} (\S+)$/m);
const lag = (app: FastifyInstance) =>
  series(app, /^qauth_events_delivery_lag_seconds\{app="auth-server"\} (\S+)$/m);
const retries = (app: FastifyInstance) =>
  series(
    app,
    /^qauth_events_delivery_attempts_total\{kind="test",result="retry",app="auth-server"\} (\S+)$/m
  );

describe('the delivery role in the auth server (real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let dockerUp = false;
  let booted: BootedAuthServer | undefined;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
  }, 240_000);

  afterAll(async () => {
    await infra?.teardown();
  });

  beforeEach((ctx) => {
    if (!dockerUp) ctx.skip();
  });

  afterEach(async () => {
    await booted?.close();
    booted = undefined;
  });

  it('publishes the pending deliveries and the lag on /metrics, and both grow while a route fails', async () => {
    if (infra === undefined || jwt === undefined) throw new Error('infrastructure not started');
    // The destination lives in the default realm, whose id is known once the
    // state is reset; until then the route lists nothing.
    const realm: { id?: string } = {};
    const delivered: string[] = [];
    const down: DeliveryRoute = {
      kind: 'test',
      destinations: async () => (realm.id === undefined ? [] : [{ id: 'down', realmId: realm.id }]),
      async deliver(delivery) {
        delivered.push(delivery.eventId);
        return { ok: false, statusCode: 503, errorClass: 'http_status' };
      },
    };
    booted = await bootAuthServer(baseEnvironment(infra, jwt), { eventDeliveryRoutes: [down] });
    const { app } = booted;
    await resetE2eState(app);
    const { rows } = await app.dbPool.query<{ id: string }>(
      `SELECT id::text AS id FROM realms WHERE name = 'master'`
    );
    const realmId = rows[0].id;
    realm.id = realmId;
    await vi.waitFor(
      async () => {
        const { rows: positions } = await app.dbPool.query(
          'SELECT 1 FROM event_delivery_positions WHERE realm_id = $1',
          [realmId]
        );
        expect(positions).toHaveLength(1);
      },
      { timeout: 10_000, interval: 50 }
    );

    // On /metrics before anything waits.
    expect(await pending(app)).toBe(0);
    expect(await lag(app)).toBe(0);

    const emit = () =>
      app.repositories.events.emitInOwnTransaction({
        type: SIGNED_IN,
        realm: realmId,
        actor: { type: 'user', id: randomUUID() },
        data: { method: 'password' },
      });

    await emit();
    await emit();
    await vi.waitFor(async () => expect(await retries(app)).toBe(2), {
      timeout: 15_000,
      interval: 100,
    });
    expect(await pending(app)).toBe(2);
    const before = await lag(app);
    expect(before).toBeGreaterThan(0);

    await emit();
    await vi.waitFor(async () => expect(await retries(app)).toBe(3), {
      timeout: 15_000,
      interval: 100,
    });
    expect(await pending(app)).toBe(3);
    expect(await lag(app)).toBeGreaterThan(before);
    expect(delivered).toHaveLength(3);
  });
});
