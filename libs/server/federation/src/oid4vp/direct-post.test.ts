import { InvalidRequestError } from '@qauth-labs/shared-errors';
import { describe, expect, it } from 'vitest';

import type { CredentialFormat } from '../profiles/verifier-profile.types';
import type { DcqlQuery } from './dcql';
import {
  assertProfileUnchanged,
  MAX_PRESENTATIONS_PER_RESPONSE,
  MAX_VP_TOKEN_LENGTH,
  OID4VP_REJECTION_DESCRIPTION,
  Oid4vpTransportRejection,
  parseVpToken,
} from './direct-post';

const ISSUER_JWT = 'eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJwaWQifQ.c2ln';
const PRESENTATION = `${ISSUER_JWT}~WyJzYWx0IiwiZ2l2ZW5fbmFtZSIsIkFsaWNlIl0~`;

const PERMITTED: readonly CredentialFormat[] = ['dc+sd-jwt'];

const QUERY: DcqlQuery = {
  credentials: [{ id: 'pid', format: 'dc+sd-jwt' }],
};

const MULTI_QUERY: DcqlQuery = {
  credentials: [
    { id: 'pid', format: 'dc+sd-jwt', multiple: true },
    { id: 'badge', format: 'dc+sd-jwt' },
  ],
};

describe('parseVpToken — OID4VP 1.0 §8.1 shape', () => {
  it('parses the JSON map keyed by DCQL Credential Query id', () => {
    const parsed = parseVpToken(JSON.stringify({ pid: [PRESENTATION] }), QUERY, PERMITTED);

    expect(parsed).toEqual([{ queryId: 'pid', format: 'dc+sd-jwt', presentation: PRESENTATION }]);
  });

  it('parses several Credential Queries, honouring multiple', () => {
    const parsed = parseVpToken(
      JSON.stringify({ pid: [PRESENTATION, PRESENTATION], badge: [PRESENTATION] }),
      MULTI_QUERY,
      PERMITTED
    );

    expect(parsed.map((p) => p.queryId)).toEqual(['pid', 'pid', 'badge']);
  });

  it('rejects the superseded Draft-22 shape (a bare string)', () => {
    expect(() => parseVpToken(JSON.stringify(PRESENTATION), QUERY, PERMITTED)).toThrow(
      Oid4vpTransportRejection
    );
  });

  it('rejects a JSON array', () => {
    expect(() => parseVpToken(JSON.stringify([PRESENTATION]), QUERY, PERMITTED)).toThrow(
      Oid4vpTransportRejection
    );
  });

  it('rejects invalid JSON', () => {
    expect(() => parseVpToken('{not json', QUERY, PERMITTED)).toThrow(/not valid JSON/);
  });

  it('rejects an entry that was never requested', () => {
    expect(() =>
      parseVpToken(JSON.stringify({ pid: [PRESENTATION], other: [PRESENTATION] }), QUERY, PERMITTED)
    ).toThrow(/not requested by the DCQL query/);
  });

  it('rejects a response missing a requested Credential Query', () => {
    expect(() =>
      parseVpToken(JSON.stringify({ pid: [PRESENTATION] }), MULTI_QUERY, PERMITTED)
    ).toThrow(/no entry for the requested Credential Query 'badge'/);
  });

  it('rejects a non-array entry (§8.1 values are arrays)', () => {
    expect(() => parseVpToken(JSON.stringify({ pid: PRESENTATION }), QUERY, PERMITTED)).toThrow(
      /is not an array/
    );
  });

  it('rejects an empty array', () => {
    expect(() => parseVpToken(JSON.stringify({ pid: [] }), QUERY, PERMITTED)).toThrow(
      /empty array/
    );
  });

  it("rejects several Presentations when the query did not set 'multiple'", () => {
    expect(() =>
      parseVpToken(JSON.stringify({ pid: [PRESENTATION, PRESENTATION] }), QUERY, PERMITTED)
    ).toThrow(/did not set 'multiple'/);
  });

  it('rejects an entry the format adapter does not recognise', () => {
    expect(() => parseVpToken(JSON.stringify({ pid: ['garbage'] }), QUERY, PERMITTED)).toThrow(
      Oid4vpTransportRejection
    );
  });

  it('rejects a format the active profile no longer permits', () => {
    expect(() => parseVpToken(JSON.stringify({ pid: [PRESENTATION] }), QUERY, [])).toThrow(
      /no usable format adapter/
    );
  });

  it('rejects an oversized vp_token before parsing it', () => {
    expect(() => parseVpToken('x'.repeat(MAX_VP_TOKEN_LENGTH + 1), QUERY, PERMITTED)).toThrow(
      /exceeds/
    );
  });

  it('bounds the total number of Presentations', () => {
    const entries = Array.from({ length: MAX_PRESENTATIONS_PER_RESPONSE + 1 }, () => PRESENTATION);

    expect(() =>
      parseVpToken(
        JSON.stringify({ pid: entries }),
        { credentials: [{ id: 'pid', format: 'dc+sd-jwt', multiple: true }] },
        PERMITTED
      )
    ).toThrow(/more than/);
  });
});

describe('parseVpToken — the safety boundary', () => {
  it('returns opaque, unverified Presentations and never a subject', () => {
    const [parsed] = parseVpToken(JSON.stringify({ pid: [PRESENTATION] }), QUERY, PERMITTED);

    expect(Object.keys(parsed).sort()).toEqual(['format', 'presentation', 'queryId']);
    expect(parsed).not.toHaveProperty('subject');
    expect(parsed).not.toHaveProperty('externalSub');
    expect(parsed).not.toHaveProperty('claims');
    expect(parsed).not.toHaveProperty('issuer');
    expect(parsed.presentation).toBe(PRESENTATION);
  });

  it('accepts a Presentation with an unverifiable signature — validation is #234', () => {
    const forged = 'eyJhbGciOiJub25lIn0.eyJ2Y3QiOiJhbnl0aGluZyJ9.AAAA~';

    expect(() => parseVpToken(JSON.stringify({ pid: [forged] }), QUERY, PERMITTED)).not.toThrow();
  });
});

describe('Oid4vpTransportRejection — non-enumerating by construction', () => {
  const reasons = [
    'state did not redeem (unknown, expired, or already consumed)',
    'vp_token is not valid JSON',
    "request was built under verifier profile 'a' but 'b' is now in force",
  ];

  it('renders the SAME client error for every distinct server-side reason', () => {
    const rendered = reasons.map((reason) => {
      const client = new Oid4vpTransportRejection(reason).toClientError();
      return JSON.stringify({
        message: client.message,
        description: client.errorDescription,
        status: client.statusCode,
        code: client.code,
      });
    });

    expect(new Set(rendered).size).toBe(1);
  });

  it('produces an RFC 6749 invalid_request with the fixed description', () => {
    const client = new Oid4vpTransportRejection('anything').toClientError();

    expect(client).toBeInstanceOf(InvalidRequestError);
    expect(client.message).toBe('invalid_request');
    expect(client.statusCode).toBe(400);
    expect(client.errorDescription).toBe(OID4VP_REJECTION_DESCRIPTION);
  });

  it('keeps the detailed reason server-side only', () => {
    const rejection = new Oid4vpTransportRejection('state 0xdeadbeef is already redeemed');

    expect(rejection.logReason).toContain('0xdeadbeef');
    expect(rejection.toClientError().errorDescription).not.toContain('0xdeadbeef');
  });
});

describe('assertProfileUnchanged', () => {
  it('accepts a response whose request was built under the same posture', () => {
    expect(() => assertProfileUnchanged('oid4vp-1.0-base', 'oid4vp-1.0-base')).not.toThrow();
  });

  it('refuses a response whose posture changed mid-flight', () => {
    expect(() => assertProfileUnchanged('oid4vp-1.0-base', 'haip-1.0')).toThrow(
      Oid4vpTransportRejection
    );
  });
});
