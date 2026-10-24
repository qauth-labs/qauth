import { describe, expect, it } from 'vitest';

import {
  ActiveKeyConflictError,
  KeyChangeRefusedError,
  KeyCreationRefusedError,
  KeyIdConflictError,
  NextKeyConflictError,
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

describe('NextKeyConflictError', () => {
  it('names the purpose and algorithm and reports a conflict', () => {
    const error = new NextKeyConflictError('upstream_client_assertion', 'ES256');

    expect(error).toBeInstanceOf(NextKeyConflictError);
    expect(error.name).toBe('NextKeyConflictError');
    expect(error.purpose).toBe('upstream_client_assertion');
    expect(error.algorithm).toBe('ES256');
    expect(error.message).toContain("'upstream_client_assertion'");
    expect(error.code).toBe('NEXT_KEY_CONFLICT');
    expect(error.statusCode).toBe(409);
  });
});

describe('KeyChangeRefusedError', () => {
  it('reports a malformed request as a client error', () => {
    const error = new KeyChangeRefusedError('UNSCOPED_PURPOSE', 'refused');

    expect(error).toBeInstanceOf(KeyChangeRefusedError);
    expect(error.name).toBe('KeyChangeRefusedError');
    expect(error.code).toBe('KEY_CHANGE_REFUSED');
    expect(error.reason).toBe('UNSCOPED_PURPOSE');
    expect(error.statusCode).toBe(400);
    expect(error.notBefore).toBeUndefined();
  });

  it.each(['NO_NEXT_KEY', 'OVERLAP_NOT_ELAPSED', 'KEY_CHANGED'] as const)(
    'reports %s, a state of the stored keys, as a conflict',
    (reason) => {
      expect(new KeyChangeRefusedError(reason, 'refused', 1).statusCode).toBe(409);
    }
  );

  it('carries the moment the step may run', () => {
    expect(new KeyChangeRefusedError('OVERLAP_NOT_ELAPSED', 'wait', 1_800_000).notBefore).toBe(
      1_800_000
    );
  });
});
