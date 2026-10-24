import { describe, expect, it } from 'vitest';

import { MisdirectedRequestError } from './misdirected-request.error';

describe('MisdirectedRequestError', () => {
  it('carries the code/statusCode contract every domain error in this package has', () => {
    const err = new MisdirectedRequestError();

    expect(err).toBeInstanceOf(MisdirectedRequestError);
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('MisdirectedRequestError');
    expect(err.statusCode).toBe(421);
    expect(err.code).toBe('MISDIRECTED_REQUEST');
  });

  it('keeps the host and the reason on details, out of the fixed message', () => {
    const err = new MisdirectedRequestError({ reason: 'realm_disabled', host: 'b.example.com' });

    expect(err.message).toBe('This server does not answer for the requested host');
    expect(err.details).toEqual({ reason: 'realm_disabled', host: 'b.example.com' });
  });

  it('omits details when none were supplied', () => {
    expect(new MisdirectedRequestError().details).toBeUndefined();
  });
});
