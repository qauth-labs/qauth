import { describe, expect, it } from 'vitest';

import {
  ActiveKeyConflictError,
  KeyCreationRefusedError,
  KeyIdConflictError,
} from './key-creation-errors';

describe('KeyCreationRefusedError', () => {
  it('carries its reason, a stable code and a client-error status', () => {
    const error = new KeyCreationRefusedError('FEDERATION_OPERATOR_ONLY', 'refused');

    expect(error).toBeInstanceOf(KeyCreationRefusedError);
    expect(error).toBeInstanceOf(Error);
    expect(error.name).toBe('KeyCreationRefusedError');
    expect(error.message).toBe('refused');
    expect(error.reason).toBe('FEDERATION_OPERATOR_ONLY');
    expect(error.code).toBe('KEY_CREATION_REFUSED');
    expect(error.statusCode).toBe(400);
  });
});

describe('KeyIdConflictError', () => {
  it('names the kid already in use and reports a conflict', () => {
    const error = new KeyIdConflictError('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs');

    expect(error).toBeInstanceOf(KeyIdConflictError);
    expect(error.name).toBe('KeyIdConflictError');
    expect(error.kid).toBe('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs');
    expect(error.message).toContain(error.kid);
    expect(error.code).toBe('KEY_ID_CONFLICT');
    expect(error.statusCode).toBe(409);
  });
});

describe('ActiveKeyConflictError', () => {
  it('names the purpose and algorithm and reports a conflict', () => {
    const error = new ActiveKeyConflictError('webhook_signing', 'HS256');

    expect(error).toBeInstanceOf(ActiveKeyConflictError);
    expect(error.name).toBe('ActiveKeyConflictError');
    expect(error.purpose).toBe('webhook_signing');
    expect(error.algorithm).toBe('HS256');
    expect(error.message).toContain("'webhook_signing'");
    expect(error.code).toBe('ACTIVE_KEY_CONFLICT');
    expect(error.statusCode).toBe(409);
  });
});
