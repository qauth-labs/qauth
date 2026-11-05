import { EgressError, type EgressRequest, type EgressResponse } from '@qauth-labs/server-egress';
import { describe, expect, it, vi } from 'vitest';

import { passwordSha1 } from './digest';
import { BreachLookupError } from './errors';
import {
  BREACH_RANGE_LIMITS,
  BREACH_RANGE_PURPOSE,
  createBreachRangeLookup,
  rangeLists,
} from './range-lookup';

const URL_BASE = 'https://api.pwnedpasswords.com/range/';

/** A password and its SHA-1 (computed apart, with `sha1sum`), split as the lookup splits it. */
const PASSWORD = 'Tr0ub4dor&3-hunter2';
const DIGEST = '48D3F85C7E1D0A358AE2D1609A37CB612303E3CB';
const PREFIX = '48D3F';
const SUFFIX = '85C7E1D0A358AE2D1609A37CB612303E3CB';

function response(body: string, status = 200): EgressResponse {
  return { status, headers: {}, body: Buffer.from(body, 'latin1'), url: URL_BASE, redirects: 0 };
}

/** A padded range as Have I Been Pwned answers it, holding `entries` and two padding lines. */
function rangeBody(entries: readonly string[]): string {
  return [
    '0018A45C4D1DEF81644B54AB7F969B88D65:10',
    ...entries,
    'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0:0',
    'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF1:0',
  ].join('\r\n');
}

function fakeEgress(answer: EgressResponse | Error = response(rangeBody([`${SUFFIX}:9659365`]))) {
  // The call is read back from `request.mock.calls`.
  const request = vi.fn<(call: EgressRequest) => Promise<EgressResponse>>(async () => {
    if (answer instanceof Error) throw answer;
    return answer;
  });
  return { request };
}

function egressError(outcome: 'blocked' | 'failed', reason: EgressError['reason']): EgressError {
  return new EgressError({
    reason,
    outcome,
    purpose: BREACH_RANGE_PURPOSE,
    host: 'api.pwnedpasswords.com',
    message: `egress to api.pwnedpasswords.com ${outcome}`,
  });
}

async function lookupError(promise: Promise<unknown>): Promise<BreachLookupError> {
  const error = await promise.then(
    () => undefined,
    (caught: unknown) => caught
  );
  expect(error).toBeInstanceOf(BreachLookupError);
  return error as BreachLookupError;
}

describe('the range lookup sends a five-character prefix only (#635 acceptance)', () => {
  it('makes one request through the egress client, holding exactly the first five hex characters', async () => {
    expect(passwordSha1(PASSWORD)).toBe(DIGEST);
    const egress = fakeEgress();
    const lookup = createBreachRangeLookup({ egress, url: URL_BASE });

    expect(await lookup.lookup(passwordSha1(PASSWORD), { realm: 'acme' })).toBe('listed');

    expect(egress.request).toHaveBeenCalledTimes(1);
    const call = egress.request.mock.calls[0]?.[0] as EgressRequest;
    const url = new URL(call.url);
    expect(url.href).toBe(`${URL_BASE}${PREFIX}`);
    expect(url.pathname.endsWith(`/${PREFIX}`)).toBe(true);
    expect(url.search).toBe('');
    expect(url.hash).toBe('');

    // Nothing of the request, wherever it is put, holds more of the digest
    // or the password: neither the full digest, nor its 35-character
    // remainder, in either case, nor the password.
    const sent = JSON.stringify({ ...call, url: String(call.url) });
    for (const secret of [DIGEST, SUFFIX, PASSWORD]) {
      expect(sent).not.toContain(secret);
      expect(sent.toLowerCase()).not.toContain(secret.toLowerCase());
    }
    expect(call.body).toBeUndefined();
    expect(call).toEqual({
      method: 'GET',
      url: `${URL_BASE}${PREFIX}`,
      headers: { 'add-padding': 'true' },
      purpose: 'breached-password-range',
      source: 'operator',
      realm: 'acme',
      limits: BREACH_RANGE_LIMITS,
    });
    expect(call.limits?.maxRedirects).toBe(0);
  });

  it('sends the prefix upper case whatever case the digest is given in, and no realm when none is given', async () => {
    const egress = fakeEgress();
    const lookup = createBreachRangeLookup({ egress, url: URL_BASE });

    await lookup.lookup(DIGEST.toLowerCase());

    const call = egress.request.mock.calls[0]?.[0] as EgressRequest;
    expect(call.url).toBe(`${URL_BASE}${PREFIX}`);
    expect('realm' in call).toBe(false);
  });

  it('caps the call: no redirect, a short deadline, an answer of 256 KiB at most', () => {
    expect(BREACH_RANGE_LIMITS).toEqual({
      maxRedirects: 0,
      connectTimeoutMs: 2_000,
      totalTimeoutMs: 3_000,
      maxResponseBytes: 256 * 1024,
    });
  });

  it('appends the prefix to the path of a bare origin, never to its host', async () => {
    const egress = fakeEgress();
    const lookup = createBreachRangeLookup({ egress, url: 'https://pwned.internal.example:8443' });

    await lookup.lookup(DIGEST);

    const call = egress.request.mock.calls[0]?.[0] as EgressRequest;
    expect(call.url).toBe(`https://pwned.internal.example:8443/${PREFIX}`);
    expect(new URL(call.url).hostname).toBe('pwned.internal.example');
  });

  it('refuses a value that is not a SHA-1 digest before sending anything', async () => {
    const egress = fakeEgress();
    const lookup = createBreachRangeLookup({ egress, url: URL_BASE });

    for (const value of [PASSWORD, DIGEST.slice(0, 39), `${DIGEST}0`, `${DIGEST.slice(0, 39)}G`]) {
      await expect(lookup.lookup(value)).rejects.toThrow(TypeError);
    }
    expect(egress.request).not.toHaveBeenCalled();
  });
});

describe('createBreachRangeLookup: the URL', () => {
  it('accepts an absolute https URL', () => {
    for (const url of [
      URL_BASE,
      'https://pwned.internal.example/v3/range/',
      'https://10.0.0.5:8443',
    ]) {
      expect(() => createBreachRangeLookup({ egress: fakeEgress(), url })).not.toThrow();
    }
  });

  it('throws a TypeError for anything else, so the boot fails', () => {
    for (const url of [
      'http://api.pwnedpasswords.com/range/',
      'api.pwnedpasswords.com/range/',
      '',
      'https://user:pass@api.pwnedpasswords.com/range/',
      'https://api.pwnedpasswords.com/range/?prefix=',
      'https://api.pwnedpasswords.com/range/?',
      'https://api.pwnedpasswords.com/range/#',
      'https://api.pwnedpasswords.com/range',
    ]) {
      expect(() => createBreachRangeLookup({ egress: fakeEgress(), url }), url).toThrow(TypeError);
    }
  });
});

describe('the range answer', () => {
  it('lists a suffix with a count above 0, in either case, with CRLF or LF', () => {
    expect(rangeLists(Buffer.from(rangeBody([`${SUFFIX}:3`])), SUFFIX)).toBe(true);
    expect(rangeLists(Buffer.from(rangeBody([`${SUFFIX.toLowerCase()}:3`])), SUFFIX)).toBe(true);
    expect(rangeLists(Buffer.from(`${SUFFIX}:1\n`), SUFFIX)).toBe(true);
    expect(rangeLists(Buffer.from(`${SUFFIX}:1\r\n`), SUFFIX)).toBe(true);
    expect(rangeLists(Buffer.from(`${SUFFIX}:1`), SUFFIX)).toBe(true);
  });

  it('does not list a suffix that is absent, or present as padding with a count of 0', () => {
    expect(rangeLists(Buffer.from(rangeBody([])), SUFFIX)).toBe(false);
    expect(rangeLists(Buffer.from(rangeBody([`${SUFFIX}:0`])), SUFFIX)).toBe(false);
    expect(rangeLists(Buffer.from(rangeBody([`${SUFFIX}:000`])), SUFFIX)).toBe(false);
    // A line for another suffix sharing all but the last character.
    expect(rangeLists(Buffer.from(rangeBody([`${SUFFIX.slice(0, 34)}0:5`])), SUFFIX)).toBe(false);
  });

  it('refuses a body that is not a range, whatever else it holds', () => {
    for (const body of [
      '',
      '\r\n',
      '<html>Service Unavailable</html>',
      `${SUFFIX}`,
      `${SUFFIX}:`,
      `${SUFFIX}:-1`,
      `${SUFFIX}:1.5`,
      `${SUFFIX}0:1`,
      `${SUFFIX.slice(1)}:1`,
      `${SUFFIX}:1\r\n\r\n${SUFFIX}:2`,
      `${SUFFIX}:1\r\nnot a line`,
      ` ${SUFFIX}:1`,
      `${SUFFIX.slice(0, 34)}é:1`,
    ]) {
      expect(() => rangeLists(Buffer.from(body, 'utf8'), SUFFIX), JSON.stringify(body)).toThrow(
        expect.objectContaining({ reason: 'bad_response' })
      );
    }
  });

  it('answers through the lookup: listed, not listed, bad response', async () => {
    const listed = createBreachRangeLookup({ egress: fakeEgress(), url: URL_BASE });
    expect(await listed.lookup(DIGEST)).toBe('listed');

    const absent = createBreachRangeLookup({
      egress: fakeEgress(response(rangeBody([]))),
      url: URL_BASE,
    });
    expect(await absent.lookup(DIGEST)).toBe('not_listed');

    const garbage = createBreachRangeLookup({
      egress: fakeEgress(response('<html></html>')),
      url: URL_BASE,
    });
    expect((await lookupError(garbage.lookup(DIGEST))).reason).toBe('bad_response');
  });
});

describe('the range lookup: failures', () => {
  it('is lookup_failed for a status other than 200, naming the status and not the prefix', async () => {
    for (const status of [204, 301, 404, 429, 500, 503]) {
      const lookup = createBreachRangeLookup({
        egress: fakeEgress(response(rangeBody([`${SUFFIX}:3`]), status)),
        url: URL_BASE,
      });
      const error = await lookupError(lookup.lookup(DIGEST));
      expect(error.reason).toBe('lookup_failed');
      expect(error.message).toContain(String(status));
      expect(error.message).not.toContain(PREFIX);
    }
  });

  it('is lookup_blocked for an egress refusal and lookup_failed for an egress failure', async () => {
    const cases: [EgressError, string][] = [
      [egressError('blocked', 'address'), 'lookup_blocked'],
      [egressError('blocked', 'redirect'), 'lookup_blocked'],
      [egressError('blocked', 'size'), 'lookup_blocked'],
      [egressError('failed', 'timeout'), 'lookup_failed'],
      [egressError('failed', 'network'), 'lookup_failed'],
      [egressError('failed', 'busy'), 'lookup_failed'],
    ];
    for (const [cause, reason] of cases) {
      const lookup = createBreachRangeLookup({ egress: fakeEgress(cause), url: URL_BASE });
      const error = await lookupError(lookup.lookup(DIGEST));
      expect(error.reason, cause.reason).toBe(reason);
      expect(error.cause).toBe(cause);
      expect(error.message).not.toContain(PREFIX);
    }
  });

  it('is lookup_failed for any other error of the client', async () => {
    const lookup = createBreachRangeLookup({
      egress: fakeEgress(new TypeError('egress realm must be a realm name')),
      url: URL_BASE,
    });
    expect((await lookupError(lookup.lookup(DIGEST))).reason).toBe('lookup_failed');
  });
});
