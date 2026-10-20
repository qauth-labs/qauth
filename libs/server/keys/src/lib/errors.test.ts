import { describe, expect, it } from 'vitest';

import {
  isKeyCustodyError,
  KekAccessDeniedError,
  KekUnavailableError,
  KEY_DECRYPTION_ERROR_MESSAGE,
  KeyCustodyError,
  KeyDecryptionError,
  UnknownKekRefError,
} from './errors';

describe('key-custody errors', () => {
  it.each([
    [new KeyDecryptionError({ detail: 'x' }), 'KEY_DECRYPTION_FAILED', 'KeyDecryptionError'],
    [new UnknownKekRefError('0123456789abcdef'), 'KEK_UNKNOWN_REF', 'UnknownKekRefError'],
    [new KekUnavailableError(), 'KEK_UNAVAILABLE', 'KekUnavailableError'],
    [new KekAccessDeniedError(), 'KEK_ACCESS_DENIED', 'KekAccessDeniedError'],
  ] as const)('%s carries its code, its name and a 500 status', (error, code, name) => {
    expect(error).toBeInstanceOf(KeyCustodyError);
    expect(error).toBeInstanceOf(Error);
    expect(error.code).toBe(code);
    expect(error.name).toBe(name);
    expect(error.statusCode).toBe(500);
    expect(isKeyCustodyError(error, code)).toBe(true);
  });

  it('keeps the detail of a decryption failure off its message', () => {
    const error = new KeyDecryptionError({ detail: 'data key did not authenticate' });

    expect(error.message).toBe(KEY_DECRYPTION_ERROR_MESSAGE);
    expect(error.detail).toBe('data key did not authenticate');
  });

  it('names the unknown kekRef on a field, not in the message', () => {
    const error = new UnknownKekRefError('0123456789abcdef');

    expect(error.kekRef).toBe('0123456789abcdef');
    expect(error.message).not.toContain('0123456789abcdef');
  });

  it('marks an unavailable backend as retryable and keeps the cause', () => {
    const cause = new Error('ThrottlingException');
    const error = new KekUnavailableError({ cause });

    expect(error.retryable).toBe(true);
    expect(error.cause).toBe(cause);
  });
});

describe('isKeyCustodyError', () => {
  it('recognises an error from another copy of this library by its code', () => {
    const fromAnotherCopy = Object.assign(new Error('Key material could not be decrypted'), {
      code: 'KEY_DECRYPTION_FAILED',
    });

    expect(isKeyCustodyError(fromAnotherCopy)).toBe(true);
    expect(isKeyCustodyError(fromAnotherCopy, 'KEY_DECRYPTION_FAILED')).toBe(true);
    expect(isKeyCustodyError(fromAnotherCopy, 'KEK_UNKNOWN_REF')).toBe(false);
  });

  it('refuses anything else', () => {
    expect(isKeyCustodyError(new Error('plain'))).toBe(false);
    expect(isKeyCustodyError(Object.assign(new Error('x'), { code: 'ENOENT' }))).toBe(false);
    expect(isKeyCustodyError({ code: 'KEY_DECRYPTION_FAILED' })).toBe(false);
    expect(isKeyCustodyError(undefined)).toBe(false);
  });
});
