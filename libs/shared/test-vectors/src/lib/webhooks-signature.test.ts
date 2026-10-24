import { createHmac } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { loadVectors } from './load';

/**
 * The Standard Webhooks vectors, checked against an HMAC computed here with
 * `node:crypto` rather than the reference library that generated them. QAuth
 * has no webhook signer yet; when it has one, its tests run these vectors
 * too.
 */
interface SignatureInput {
  secret: string;
  id: string;
  timestamp: number;
  body: string;
}

const vectors = loadVectors<SignatureInput, { signature: string }>('webhooks/signature');

const keyOf = (secret: string) => Buffer.from(secret.replace(/^whsec_/, ''), 'base64');

function sign({ secret, id, timestamp, body }: SignatureInput): { signature: string } {
  const mac = createHmac('sha256', keyOf(secret)).update(`${id}.${timestamp}.${body}`, 'utf8');
  return { signature: `v1,${mac.digest('base64')}` };
}

describe('webhooks/signature vectors (Standard Webhooks)', () => {
  it.each(vectors.cases)('$id', ({ input, expected }) => {
    expect(sign(input)).toEqual(expected);
  });

  it('marks every secret but the public reference example as a throwaway test secret', () => {
    const secrets = vectors.cases
      .filter((c) => c.id !== 'reference-library-example')
      .map((c) => keyOf(c.input.secret).toString('ascii'));
    expect(secrets.length).toBeGreaterThan(0);
    for (const secret of secrets) expect(secret).toMatch(/throwaway test/);
  });
});
