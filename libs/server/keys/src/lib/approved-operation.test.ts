import { describe, expect, it } from 'vitest';

import {
  canonicalOperationBytes,
  isOperationNonce,
  isSecurityOperationActor,
  KEY_ROTATE_OPERATION,
  keyRotationOperation,
  type KeyRotationOperationInput,
  type KeyRotationOperationRecord,
  newOperationNonce,
  OPERATION_NONCE_BYTES,
  OperationApprovalError,
  operationDigest,
} from './approved-operation';

/** 32 bytes, 0x00 to 0x1f. */
const NONCE = Buffer.from(Array.from({ length: 32 }, (_, index) => index)).toString('base64url');
const REALM = '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e01';
const ADMIN = {
  kind: 'human',
  realmId: '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e00',
  accountId: '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6eaa',
} as const;

function input(overrides: Partial<KeyRotationOperationInput> = {}): KeyRotationOperationInput {
  return { realmId: REALM, purpose: 'token_signing', requester: ADMIN, nonce: NONCE, ...overrides };
}

describe('the canonical record of a manual key rotation', () => {
  it('has stable bytes: a golden test pins them, and the digest taken over them', () => {
    // The realm id in upper case is the same realm: the record holds it in lower case.
    const record = keyRotationOperation(input({ realmId: REALM.toUpperCase() }));
    expect(canonicalOperationBytes(record).toString('utf8')).toBe(
      '{"nonce":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","op":"keys.rotate",' +
        '"purpose":"token_signing","realm":"0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e01",' +
        '"requester":{"accountId":"0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6eaa","kind":"human",' +
        '"realmId":"0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e00"},"scope":null}'
    );
    expect(operationDigest(record).toString('hex')).toBe(
      '11f8efd7145a099be0546cffdcca957fa2e0111f232461e14653dc7f1fa11b27'
    );
  });

  it('pins a scoped record of the break-glass CLI too, with text outside ASCII as UTF-8', () => {
    const record = keyRotationOperation(
      input({
        purpose: 'webhook_signing',
        scopeId: 'sub-é-1',
        requester: { kind: 'break_glass', operatingSystemUser: 'qauth-ops' },
      })
    );
    const bytes = canonicalOperationBytes(record);
    expect(bytes.toString('utf8')).toBe(
      '{"nonce":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","op":"keys.rotate",' +
        '"purpose":"webhook_signing","realm":"0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e01",' +
        '"requester":{"kind":"break_glass","operatingSystemUser":"qauth-ops"},"scope":"sub-é-1"}'
    );
    // é is two bytes in UTF-8, not an escape.
    expect(bytes.includes(Buffer.from([0xc3, 0xa9]))).toBe(true);
    expect(operationDigest(record).toString('hex')).toBe(
      '47f62fe2b014cf943c8c6ec9119d4b16626626dbf02a5bb505a6c949e258a369'
    );
  });

  it('contains the operation, realm, purpose, scope, requester and nonce, and nothing else', () => {
    const record = keyRotationOperation(input());
    expect(record).toEqual({
      op: KEY_ROTATE_OPERATION,
      realm: REALM,
      purpose: 'token_signing',
      scope: null,
      requester: ADMIN,
      nonce: NONCE,
    });
    expect(Object.isFrozen(record)).toBe(true);
    expect(Object.keys(JSON.parse(canonicalOperationBytes(record).toString('utf8')))).toEqual([
      'nonce',
      'op',
      'purpose',
      'realm',
      'requester',
      'scope',
    ]);
  });

  it('binds every member: another realm, purpose, scope, requester or nonce is another digest', () => {
    const base = operationDigest(keyRotationOperation(input())).toString('hex');
    const others = [
      input({ realmId: '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e02' }),
      input({ purpose: 'event_signing' }),
      input({ purpose: 'webhook_signing', scopeId: 'sub-1' }),
      input({ requester: { ...ADMIN, accountId: '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6eab' } }),
      input({ requester: { ...ADMIN, kind: 'service_account' } }),
      input({ requester: { kind: 'break_glass', operatingSystemUser: 'root' } }),
      input({ nonce: newOperationNonce() }),
    ].map((each) => operationDigest(keyRotationOperation(each)).toString('hex'));
    expect(others).not.toContain(base);
    expect(new Set(others).size).toBe(others.length);
  });

  it('hashes only the members of a record, whatever else the object carries', () => {
    const record = keyRotationOperation(input());
    const padded = {
      ...record,
      requester: { ...record.requester, extra: 'x' },
      extra: 'y',
    } as unknown as KeyRotationOperationRecord;
    expect(canonicalOperationBytes(padded)).toEqual(canonicalOperationBytes(record));
    // A record of another operation is not hashed as this one.
    const retire = { ...record, op: 'keys.retire' } as unknown as KeyRotationOperationRecord;
    expect(() => canonicalOperationBytes(retire)).toThrow(TypeError);
  });

  it.each([
    ['a realm id that is not a UUID', input({ realmId: 'realm-1' })],
    ['an unknown purpose', input({ purpose: 'signing' as never })],
    ['an empty scope id', input({ scopeId: '' })],
    ['a scope id with a lone surrogate', input({ scopeId: 'a\ud800' })],
    ['a requester of no known kind', input({ requester: { kind: 'robot' } as never })],
    ['a human requester without an account', input({ requester: { ...ADMIN, accountId: '' } })],
    [
      'an operating-system user with a control character',
      input({ requester: { kind: 'break_glass', operatingSystemUser: 'root\n' } }),
    ],
    ['a short nonce', input({ nonce: NONCE.slice(0, 40) })],
    ['a nonce in standard base64', input({ nonce: `${NONCE.slice(0, 42)}+` })],
    ['a padded nonce', input({ nonce: `${NONCE}=` })],
  ])('refuses %s', (_name, value) => {
    expect(() => keyRotationOperation(value)).toThrow(TypeError);
  });
});

describe('approval nonces and actors', () => {
  it('makes a fresh nonce of 32 bytes each time', () => {
    const first = newOperationNonce();
    expect(isOperationNonce(first)).toBe(true);
    expect(Buffer.from(first, 'base64url')).toHaveLength(OPERATION_NONCE_BYTES);
    expect(newOperationNonce()).not.toBe(first);
  });

  it('reads an actor of each kind, and nothing else', () => {
    expect(isSecurityOperationActor(ADMIN)).toBe(true);
    expect(isSecurityOperationActor({ ...ADMIN, kind: 'service_account' })).toBe(true);
    expect(isSecurityOperationActor({ kind: 'break_glass', operatingSystemUser: 'ops' })).toBe(
      true
    );
    expect(isSecurityOperationActor({ ...ADMIN, realmId: 'operator' })).toBe(false);
    expect(isSecurityOperationActor({ kind: 'break_glass' })).toBe(false);
    expect(isSecurityOperationActor(null)).toBe(false);
    expect(isSecurityOperationActor('admin')).toBe(false);
  });

  it('refuses with a 403 that names its reason', () => {
    const error = new OperationApprovalError('missing', 'no approval');
    expect(error).toMatchObject({
      statusCode: 403,
      code: 'OPERATION_APPROVAL_REFUSED',
      reason: 'missing',
      name: 'OperationApprovalError',
    });
    expect(error).toBeInstanceOf(Error);
  });
});
