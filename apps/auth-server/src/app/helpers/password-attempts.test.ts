import {
  createPasswordAttempts,
  type PasswordAttempts,
  type PasswordAttemptsDependencies,
} from '@qauth-labs/fastify-plugin-sign-in-engine';
import { describe, expect, it } from 'vitest';

import {
  clientAddressKey,
  type ClientAddressSource,
  UNKNOWN_CLIENT_ADDRESS,
} from './client-address';
import { ladderEndUserIp } from './password-attempts';

const REALM_ID = 'realm-1';
const IDENTIFIER = 'user@example.com';

/** Requests that carry no client address: each keys as `UNKNOWN_CLIENT_ADDRESS`. */
const ADDRESS_LESS: readonly ClientAddressSource[] = [
  {},
  { ip: '' },
  { ip: undefined, socket: {} },
  { ip: '', socket: { remoteAddress: '' } },
];

describe('ladderEndUserIp', () => {
  it('hands the ladder the client address key', () => {
    expect(ladderEndUserIp({ ip: '203.0.113.7' })).toEqual({ endUserIp: '203.0.113.7' });
    expect(ladderEndUserIp({ ip: '::ffff:203.0.113.7' })).toEqual({ endUserIp: '203.0.113.7' });
    // An IPv6 client by its /64, as every other per-address key.
    expect(ladderEndUserIp({ ip: '2001:db8:1:2:aaaa:bbbb:cccc:7' })).toEqual({
      endUserIp: '2001:db8:1:2::',
    });
    expect(ladderEndUserIp({ socket: { remoteAddress: '198.51.100.9' } })).toEqual({
      endUserIp: '198.51.100.9',
    });
  });

  it('hands the ladder no end-user IP when the request carries no client address', () => {
    for (const request of ADDRESS_LESS) {
      expect(clientAddressKey(request)).toBe(UNKNOWN_CLIENT_ADDRESS);
      const fields = ladderEndUserIp(request);
      expect(fields).toEqual({});
      expect(Object.hasOwn(fields, 'endUserIp')).toBe(false);
    }
  });
});

/**
 * A ladder with the known-IP rule alone: a success records the attempt's
 * end-user IP, and once the account is in its wait only a recorded IP is let
 * through. The counting and the schedule are the library's to test
 * (`failure-ladder.test.ts`, `failure-ladder.integration.test.ts`).
 */
function knownIpLadder() {
  const known = new Set<string>();
  const state = { waiting: false };
  const ladder: PasswordAttemptsDependencies['ladder'] = {
    async reserve({ endUserIp }) {
      const exempt = endUserIp !== undefined && known.has(endUserIp);
      if (state.waiting && !exempt) return { kind: 'wait', retryAfterSeconds: 8 };
      return {
        kind: 'reserved',
        async settle(outcome) {
          if (outcome === 'success' && endUserIp !== undefined) known.add(endUserIp);
          return { ceilingReached: false };
        },
      };
    },
  };
  return { ladder, known, state };
}

function gateOver(ladder: PasswordAttemptsDependencies['ladder']): PasswordAttempts {
  return createPasswordAttempts({
    identifierDigest: async ({ identifier }) => `digest-of-${identifier.length}`,
    ladder,
    hardAction: {
      ceilingReached: async () => undefined,
      clearIgnoredMark: async () => undefined,
    },
    hardActionArmed: async () => false,
    log: { error: () => undefined },
  });
}

/** One sign-in attempt from `request`, as the login routes reserve it. */
const reserveFrom = (gate: PasswordAttempts, request: ClientAddressSource) =>
  gate.reserve({ realmId: REALM_ID, identifier: IDENTIFIER, ...ladderEndUserIp(request) });

describe('the failure ladder’s known-IP exemption (#615) for a request with no client address', () => {
  it('never records an address-less sign-in as a known IP', async () => {
    const { ladder, known } = knownIpLadder();
    const gate = gateOver(ladder);

    for (const request of ADDRESS_LESS) {
      const attempt = await reserveFrom(gate, request);
      if (attempt.kind !== 'reserved') throw new Error('expected a reservation');
      await attempt.succeeded({ userId: 'user-1', ignoredMark: false });
    }
    expect(known.size).toBe(0);
    expect(known.has(UNKNOWN_CLIENT_ADDRESS)).toBe(false);
  });

  it('never exempts an address-less attempt from the wait, after any number of such sign-ins', async () => {
    const { ladder, state } = knownIpLadder();
    const gate = gateOver(ladder);

    // An address-less client and an addressed one each sign in once.
    for (const request of [{}, { ip: '203.0.113.7' }]) {
      const attempt = await reserveFrom(gate, request);
      if (attempt.kind !== 'reserved') throw new Error('expected a reservation');
      await attempt.succeeded({ userId: 'user-1', ignoredMark: false });
    }

    state.waiting = true;
    // The addressed client is known, so the exemption is live here...
    expect(await reserveFrom(gate, { ip: '203.0.113.7' })).toMatchObject({ kind: 'reserved' });
    // ...but no address-less client is, the one that signed in included.
    for (const request of ADDRESS_LESS) {
      expect(await reserveFrom(gate, request)).toEqual({ kind: 'wait', retryAfterSeconds: 8 });
    }
  });
});
