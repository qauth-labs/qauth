import { describe, expect, it } from 'vitest';

import { KeyCreationRefusedError, KeyIdConflictError } from './key-creation-errors';

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
