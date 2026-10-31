import { describe, expect, it } from 'vitest';

import {
  canonicalRequest,
  CanonicalRequestError,
  type CanonicalRequestInput,
  newApprovalNonce,
  opHashOf,
  requestHashOf,
} from './canonical-request';
import { approvalIdOf, approvalRefusal } from './gate';

/**
 * THE APPROVAL GATE'S DECISION (#512): an approval approves a call only when
 * the call's canonical request hashes to the approval's `request_hash`, and
 * only while it is approved and unexpired. One case per part of the request
 * the approval binds, and one per state that refuses.
 */

const REALM = '018f2d6e-8a8b-7c3d-9e0f-1a2b3c4d5e6f';
const OTHER_REALM = '018f2d6e-8a8b-7c3d-9e0f-1a2b3c4d5e70';
const REQUESTER = {
  kind: 'human' as const,
  realmId: REALM,
  accountId: '0190a1b2-0000-7000-8000-000000000001',
};
const NOW = 1_800_000_000_000;

const FILED: CanonicalRequestInput = {
  operationId: 'keys.rotate',
  method: 'POST',
  params: { realmId: REALM, keyId: 'signing-1' },
  query: { dryRun: 'false' },
  body: { algorithm: 'EdDSA', retireAfterDays: 7 },
  realmId: REALM,
  requester: REQUESTER,
};

/** The stored approval of `FILED`, in `status`, expiring five minutes after `NOW`. */
function storedApproval(status: 'pending' | 'approved' | 'denied' | 'cancelled' | 'consumed') {
  return {
    requestHash: requestHashOf(canonicalRequest(FILED)),
    status,
    expiresAt: NOW + 5 * 60_000,
  };
}

/** The gate's answer for the call `call`, at `now`, against the approval of `FILED` in `status`. */
function decide(
  call: CanonicalRequestInput,
  status: Parameters<typeof storedApproval>[0] = 'approved',
  now = NOW + 1_000
) {
  return approvalRefusal(storedApproval(status), requestHashOf(canonicalRequest(call)), now);
}

describe('the approval gate (#512)', () => {
  it('lets the very request the approval was filed for through', () => {
    expect(decide({ ...FILED })).toBeNull();
    // Key order, an upper-case realm id in the path and the method's case are
    // not part of the request.
    expect(
      decide({
        ...FILED,
        method: 'post',
        params: { keyId: 'signing-1', realmId: REALM.toUpperCase() },
        body: { retireAfterDays: 7, algorithm: 'EdDSA' },
      })
    ).toBeNull();
  });

  // Acceptance criterion: a changed body, a changed path parameter, another
  // realm or another requester makes the gate refuse, one case each.
  it('refuses a changed body', () => {
    expect(decide({ ...FILED, body: { algorithm: 'EdDSA', retireAfterDays: 8 } })).toBe(
      'request-mismatch'
    );
    expect(
      decide({ ...FILED, body: { algorithm: 'EdDSA', retireAfterDays: 7, extra: true } })
    ).toBe('request-mismatch');
    expect(decide({ ...FILED, body: undefined })).toBe('request-mismatch');
  });

  it('refuses a changed path parameter', () => {
    expect(decide({ ...FILED, params: { realmId: REALM, keyId: 'signing-2' } })).toBe(
      'request-mismatch'
    );
  });

  it('refuses another realm', () => {
    expect(
      decide({
        ...FILED,
        params: { realmId: OTHER_REALM, keyId: 'signing-1' },
        realmId: OTHER_REALM,
      })
    ).toBe('request-mismatch');
  });

  it('refuses another requester', () => {
    expect(
      decide({
        ...FILED,
        requester: { ...REQUESTER, accountId: '0190a1b2-0000-7000-8000-000000000002' },
      })
    ).toBe('request-mismatch');
    // The same account id in another realm is another account.
    expect(decide({ ...FILED, requester: { ...REQUESTER, realmId: OTHER_REALM } })).toBe(
      'request-mismatch'
    );
  });

  it('refuses a changed query, method or operation', () => {
    expect(decide({ ...FILED, query: { dryRun: 'true' } })).toBe('request-mismatch');
    expect(decide({ ...FILED, method: 'PUT' })).toBe('request-mismatch');
    expect(decide({ ...FILED, operationId: 'keys.retire' })).toBe('request-mismatch');
  });

  // Acceptance criterion: a consumed, expired or cancelled approval is refused.
  it('refuses a consumed approval', () => {
    expect(decide(FILED, 'consumed')).toBe('consumed');
  });

  it('refuses an expired approval, from its expiry on', () => {
    expect(decide(FILED, 'approved', NOW + 5 * 60_000 - 1)).toBeNull();
    expect(decide(FILED, 'approved', NOW + 5 * 60_000)).toBe('expired');
  });

  it('refuses a cancelled approval', () => {
    expect(decide(FILED, 'cancelled')).toBe('cancelled');
  });

  it('refuses a pending or denied approval, and an unknown one', () => {
    expect(decide(FILED, 'pending')).toBe('pending');
    expect(decide(FILED, 'denied')).toBe('denied');
    expect(approvalRefusal(undefined, requestHashOf(canonicalRequest(FILED)), NOW)).toBe(
      'not-found'
    );
  });

  it('reads one UUID from QAuth-Approval, and nothing else', () => {
    const id = '7d0f3b6e-2c1a-4e5f-9a8b-0c1d2e3f4a5b';
    expect(approvalIdOf(id)).toBe(id);
    expect(approvalIdOf(` ${id.toUpperCase()} `)).toBe(id);
    expect(approvalIdOf(undefined)).toBeNull();
    expect(approvalIdOf([id, id])).toBeNull();
    expect(approvalIdOf(`${id},${id}`)).toBeNull();
    expect(approvalIdOf('not-an-id')).toBeNull();
  });
});

describe('the canonical request (#512)', () => {
  it('binds op_hash to the server nonce, and request_hash to nothing but the request', () => {
    const request = canonicalRequest(FILED);
    const first = newApprovalNonce();
    const second = newApprovalNonce();
    expect(first.equals(second)).toBe(false);
    expect(opHashOf(request, first).equals(opHashOf(request, second))).toBe(false);
    expect(opHashOf(request, first).equals(requestHashOf(request))).toBe(false);
    expect(requestHashOf(request).equals(requestHashOf(canonicalRequest({ ...FILED })))).toBe(true);
    expect(() => opHashOf(request, Buffer.alloc(16))).toThrow(CanonicalRequestError);
  });

  it('holds every part of the request, the realm id in the path as stored', () => {
    expect(
      canonicalRequest({ ...FILED, params: { realmId: REALM.toUpperCase(), keyId: 'k' } })
    ).toEqual({
      operationId: 'keys.rotate',
      method: 'POST',
      params: { realmId: REALM, keyId: 'k' },
      query: { dryRun: 'false' },
      body: { algorithm: 'EdDSA', retireAfterDays: 7 },
      realmId: REALM,
      requester: REQUESTER,
    });
    expect(canonicalRequest({ ...FILED, query: undefined, body: undefined })).toMatchObject({
      query: {},
      body: null,
    });
  });

  it("takes the router's and the query parser's null-prototype objects as the plain ones filed", () => {
    // What Fastify hands a route with no params or querystring schema: an
    // object whose prototype is itself a null-prototype object.
    const NULL_OBJECT_PROTOTYPE = Object.create(null) as object;
    const asParsed = (members: Record<string, string>) =>
      Object.assign(Object.create(NULL_OBJECT_PROTOTYPE) as object, members);
    expect(Object.getPrototypeOf(Object.getPrototypeOf(asParsed({})))).toBeNull();
    expect(
      decide({
        ...FILED,
        params: asParsed({ realmId: REALM, keyId: 'signing-1' }),
        query: Object.assign(Object.create(null) as object, { dryRun: 'false' }),
      })
    ).toBeNull();
  });

  it('refuses a request it cannot store or canonicalize', () => {
    expect(() => canonicalRequest({ ...FILED, body: Buffer.from('bytes') })).toThrow(
      CanonicalRequestError
    );
    expect(() => canonicalRequest({ ...FILED, body: { note: 'a\u0000b' } })).toThrow(/U\+0000/);
    expect(() => canonicalRequest({ ...FILED, body: { ['a\u0000']: 1 } })).toThrow(/U\+0000/);
    expect(() => canonicalRequest({ ...FILED, body: { size: Number.NaN } })).toThrow(
      CanonicalRequestError
    );
    expect(() => canonicalRequest({ ...FILED, params: 'realm' })).toThrow(CanonicalRequestError);
    expect(() => canonicalRequest({ ...FILED, query: ['dryRun'] })).toThrow(CanonicalRequestError);
    // An object a schema's transform made says nothing through its members:
    // two different queries would hash alike.
    for (const query of [
      new URLSearchParams('force=true'),
      new Map([['force', 'true']]),
      new Date(0),
      new (class Query {
        force = 'true';
      })(),
    ]) {
      expect(() => canonicalRequest({ ...FILED, query }), String(query)).toThrow(
        CanonicalRequestError
      );
    }
    expect(() => canonicalRequest({ ...FILED, params: Buffer.from('x') })).toThrow(
      CanonicalRequestError
    );
  });
});
