import { describe, expect, it } from 'vitest';

import {
  canonicalRequest,
  CanonicalRequestError,
  type CanonicalRequestInput,
  newApprovalNonce,
  opHashOf,
} from './canonical-request';
import { approvalIdOf, approvalRefusal } from './gate';

/**
 * THE APPROVAL GATE'S DECISION (#512): an approval approves a call only when
 * the call's canonical request, hashed with the approval's stored nonce, gives
 * the approval's `op_hash`, and only while it is approved and unexpired. One
 * case per part of the request the approval binds, and one per state that
 * refuses.
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

const NONCE = newApprovalNonce();

type Status = 'pending' | 'approved' | 'denied' | 'cancelled' | 'consumed' | 'expired';

/** The stored approval of `FILED`, in `status`, expiring five minutes after `NOW`. */
function storedApproval(status: Status, nonce = NONCE, approvalsRequired = 1) {
  return {
    opHash: opHashOf(canonicalRequest(FILED), NONCE),
    nonce,
    status,
    expiresAt: NOW + 5 * 60_000,
    approvalsRequired,
  };
}

/** The gate's answer for the call `call`, at `now`, against the approval of `FILED` in `status`. */
function decide(call: CanonicalRequestInput, status: Status = 'approved', now = NOW + 1_000) {
  return approvalRefusal(storedApproval(status), canonicalRequest(call), now, 1);
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

  it('refuses a pending, denied or swept-expired approval, and an unknown one', () => {
    expect(decide(FILED, 'pending')).toBe('pending');
    expect(decide(FILED, 'denied')).toBe('denied');
    expect(decide(FILED, 'expired')).toBe('expired');
    expect(approvalRefusal(undefined, canonicalRequest(FILED), NOW, 1)).toBe('not-found');
  });

  // #521: a realm that made a second admin mandatory after the approval was
  // filed for one is not approved by it; one filed for two still is.
  it('refuses an approval filed for fewer approvals than the request needs now', () => {
    const one = storedApproval('approved', NONCE, 1);
    expect(approvalRefusal(one, canonicalRequest(FILED), NOW + 1_000, 2)).toBe(
      'requirement-raised'
    );
    const two = storedApproval('approved', NONCE, 2);
    expect(approvalRefusal(two, canonicalRequest(FILED), NOW + 1_000, 2)).toBeNull();
    expect(approvalRefusal(two, canonicalRequest(FILED), NOW + 1_000, 1)).toBeNull();
    // Another request is refused for what it is first.
    expect(approvalRefusal(one, canonicalRequest({ ...FILED, body: null }), NOW + 1_000, 2)).toBe(
      'request-mismatch'
    );
  });

  // #901: the hash binds the request only through the nonce stored with it.
  it('matches no call once the nonce is not the one op_hash was computed with', () => {
    const retired = storedApproval('approved', newApprovalNonce());
    expect(approvalRefusal(retired, canonicalRequest(FILED), NOW + 1_000, 1)).toBe(
      'request-mismatch'
    );
    // A closed approval is refused for what it is, its nonce retired or not.
    expect(
      approvalRefusal(
        storedApproval('consumed', newApprovalNonce()),
        canonicalRequest(FILED),
        NOW + 1_000,
        1
      )
    ).toBe('consumed');
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
  it('binds op_hash to the server nonce', () => {
    const request = canonicalRequest(FILED);
    const first = newApprovalNonce();
    const second = newApprovalNonce();
    expect(first.equals(second)).toBe(false);
    expect(opHashOf(request, first).equals(opHashOf(request, second))).toBe(false);
    expect(opHashOf(request, first).equals(opHashOf(canonicalRequest({ ...FILED }), first))).toBe(
      true
    );
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

  // #517: an operation that reads state is approved against the version it
  // read, so a call after the state moved does not run on that approval.
  it('binds the state version an operation that reads state was filed against', () => {
    const filed = { ...FILED, stateVersion: '7' };
    expect(canonicalRequest(filed)).toMatchObject({ stateVersion: '7' });
    const approval = {
      opHash: opHashOf(canonicalRequest(filed), NONCE),
      nonce: NONCE,
      status: 'approved' as const,
      expiresAt: NOW + 5 * 60_000,
      approvalsRequired: 1,
    };
    expect(approvalRefusal(approval, canonicalRequest(filed), NOW + 1_000, 1)).toBeNull();
    for (const stateVersion of ['8', undefined, null]) {
      expect(
        approvalRefusal(approval, canonicalRequest({ ...FILED, stateVersion }), NOW + 1_000, 1),
        String(stateVersion)
      ).toBe('request-mismatch');
    }
    // An operation that reads no state hashes as it did before.
    expect('stateVersion' in canonicalRequest({ ...FILED, stateVersion: null })).toBe(false);
    expect(decide({ ...FILED, stateVersion: undefined })).toBeNull();
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
