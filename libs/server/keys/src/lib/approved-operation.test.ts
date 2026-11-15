import { describe, expect, it } from 'vitest';

import {
  canonicalOperationBytes,
  checkedApproval,
  isKekRef,
  isKid,
  isOperationNonce,
  isSecurityOperationActor,
  KEK_ROTATE_OPERATION,
  kekRotationOperation,
  type KekRotationOperationInput,
  type KekRotationOperationRecord,
  KEY_RETIRE_OPERATION,
  KEY_ROTATE_OPERATION,
  keyRetirementOperation,
  type KeyRetirementOperationInput,
  type KeyRetirementOperationRecord,
  keyRotationOperation,
  type KeyRotationOperationInput,
  type KeyRotationOperationRecord,
  MAX_KEK_REF_LENGTH,
  MAX_KID_LENGTH,
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
    const other = { ...record, op: 'keys.disable' } as unknown as KeyRotationOperationRecord;
    expect(() => canonicalOperationBytes(other)).toThrow(TypeError);
    // Nor is a rotation's record relabelled as a retirement: it names no kid.
    const retire = { ...record, op: KEY_RETIRE_OPERATION } as unknown as KeyRotationOperationRecord;
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

function kekInput(overrides: Partial<KekRotationOperationInput> = {}): KekRotationOperationInput {
  return {
    from: '3f1c0b2a9d8e7f60',
    to: 'a1b2c3d4e5f60718',
    requester: ADMIN,
    nonce: NONCE,
    ...overrides,
  };
}

describe('the canonical record of a KEK rotation (#545)', () => {
  it('has stable bytes: a golden test pins them, and the digest taken over them', () => {
    // The requester's realm id in upper case is the same realm: the record holds it in lower case.
    const record = kekRotationOperation(
      kekInput({ requester: { ...ADMIN, realmId: ADMIN.realmId.toUpperCase() } })
    );
    expect(canonicalOperationBytes(record).toString('utf8')).toBe(
      '{"from":"3f1c0b2a9d8e7f60","nonce":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",' +
        '"op":"kek.rotate","requester":{"accountId":"0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6eaa",' +
        '"kind":"human","realmId":"0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e00"},"to":"a1b2c3d4e5f60718"}'
    );
    expect(operationDigest(record).toString('hex')).toBe(
      '0f66d78bb036980ef83d5b37eae4f2753cf19d46b87fab5395c0b6be3d7344ed'
    );
  });

  it("pins the operator command's record of a key service's versions too", () => {
    const record = kekRotationOperation(
      kekInput({
        from: 'vault:transit/keys/qauth-kek#v1',
        to: 'vault:transit/keys/qauth-kek#v2',
        requester: { kind: 'break_glass', operatingSystemUser: 'qauth-ops' },
      })
    );
    expect(canonicalOperationBytes(record).toString('utf8')).toBe(
      '{"from":"vault:transit/keys/qauth-kek#v1","nonce":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",' +
        '"op":"kek.rotate","requester":{"kind":"break_glass","operatingSystemUser":"qauth-ops"},' +
        '"to":"vault:transit/keys/qauth-kek#v2"}'
    );
    expect(operationDigest(record).toString('hex')).toBe(
      '04470cec4b28a9a186ff438e103d0c3cb57f1c2e5f16a46838a3172f1494b443'
    );
  });

  it('contains the operation, both references, the requester and the nonce, and no realm', () => {
    const record = kekRotationOperation(kekInput());
    expect(record).toEqual({
      op: KEK_ROTATE_OPERATION,
      from: '3f1c0b2a9d8e7f60',
      to: 'a1b2c3d4e5f60718',
      requester: ADMIN,
      nonce: NONCE,
    });
    expect(Object.isFrozen(record)).toBe(true);
  });

  it('binds every member: another source, target, requester or nonce is another digest', () => {
    const base = operationDigest(kekRotationOperation(kekInput())).toString('hex');
    const others = [
      kekInput({ from: '3f1c0b2a9d8e7f61' }),
      kekInput({ to: 'a1b2c3d4e5f60719' }),
      // The two references swapped: the rotation back is another operation.
      kekInput({ from: 'a1b2c3d4e5f60718', to: '3f1c0b2a9d8e7f60' }),
      kekInput({ requester: { kind: 'break_glass', operatingSystemUser: 'root' } }),
      kekInput({ nonce: newOperationNonce() }),
    ].map((each) => operationDigest(kekRotationOperation(each)).toString('hex'));
    expect(others).not.toContain(base);
    expect(new Set(others).size).toBe(others.length);
    // A manual key rotation never hashes to a KEK rotation's digest.
    expect(others).not.toContain(operationDigest(keyRotationOperation(input())).toString('hex'));
  });

  it('hashes only the members of a record, whatever else the object carries', () => {
    const record = kekRotationOperation(kekInput());
    const padded = {
      ...record,
      realm: REALM,
      requester: { ...record.requester, extra: 'x' },
    } as unknown as KekRotationOperationRecord;
    expect(canonicalOperationBytes(padded)).toEqual(canonicalOperationBytes(record));
  });

  it.each([
    ['an empty source', kekInput({ from: '' })],
    ['a target with a control character', kekInput({ to: 'a1b2\u0000' })],
    ['a reference over the length limit', kekInput({ to: 'a'.repeat(MAX_KEK_REF_LENGTH + 1) })],
    ['a reference with a lone surrogate', kekInput({ from: 'kek\ud800' })],
    ['the same reference twice', kekInput({ to: '3f1c0b2a9d8e7f60' })],
    ['a requester of no known kind', kekInput({ requester: { kind: 'robot' } as never })],
    ['a short nonce', kekInput({ nonce: NONCE.slice(0, 40) })],
  ])('refuses %s', (_name, value) => {
    expect(() => kekRotationOperation(value)).toThrow(TypeError);
  });

  it('reads a KEK reference of the shipped providers, and nothing that is no text', () => {
    expect(isKekRef('3f1c0b2a9d8e7f60')).toBe(true);
    expect(isKekRef('vault:transit/keys/qauth-kek#v2')).toBe(true);
    expect(isKekRef('a'.repeat(MAX_KEK_REF_LENGTH))).toBe(true);
    expect(isKekRef(42)).toBe(false);
    expect(isKekRef(undefined)).toBe(false);
  });
});

const KID = 'Zr9kq2v_Y3lJm8T0dWbXo1sNcPfQhUaE-4gRiKxL7';

function retireInput(
  overrides: Partial<KeyRetirementOperationInput> = {}
): KeyRetirementOperationInput {
  return { realmId: REALM, kid: KID, requester: ADMIN, nonce: NONCE, ...overrides };
}

describe('the canonical record of an emergency key retirement (#551)', () => {
  it('has stable bytes: a golden test pins them, and the digest taken over them', () => {
    // The realm id in upper case is the same realm: the record holds it in lower case.
    const record = keyRetirementOperation(retireInput({ realmId: REALM.toUpperCase() }));
    expect(canonicalOperationBytes(record).toString('utf8')).toBe(
      '{"kid":"Zr9kq2v_Y3lJm8T0dWbXo1sNcPfQhUaE-4gRiKxL7",' +
        '"nonce":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","op":"keys.retire",' +
        '"realm":"0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e01",' +
        '"requester":{"accountId":"0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6eaa","kind":"human",' +
        '"realmId":"0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e00"}}'
    );
    expect(operationDigest(record).toString('hex')).toBe(
      'd0a759d2bf4f0d6c657cc63fbded4b712fefa6ec45036237ded5e703b867f7df'
    );
  });

  it("pins the break-glass CLI's record too", () => {
    const record = keyRetirementOperation(
      retireInput({ requester: { kind: 'break_glass', operatingSystemUser: 'qauth-ops' } })
    );
    expect(canonicalOperationBytes(record).toString('utf8')).toBe(
      '{"kid":"Zr9kq2v_Y3lJm8T0dWbXo1sNcPfQhUaE-4gRiKxL7",' +
        '"nonce":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","op":"keys.retire",' +
        '"realm":"0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e01",' +
        '"requester":{"kind":"break_glass","operatingSystemUser":"qauth-ops"}}'
    );
    expect(operationDigest(record).toString('hex')).toBe(
      '9cc0824fceae90b8a87aa0139d453635107bcf052946a6dec15e28264aacf1d4'
    );
  });

  it('contains the operation, realm, kid, requester and nonce, and nothing else', () => {
    const record = keyRetirementOperation(retireInput());
    expect(record).toEqual({
      op: KEY_RETIRE_OPERATION,
      realm: REALM,
      kid: KID,
      requester: ADMIN,
      nonce: NONCE,
    });
    expect(Object.isFrozen(record)).toBe(true);
  });

  it('binds every member: another realm, kid, requester or nonce is another digest', () => {
    const base = operationDigest(keyRetirementOperation(retireInput())).toString('hex');
    const others = [
      retireInput({ realmId: '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e02' }),
      // A kid is compared byte for byte: another case is another key.
      retireInput({ kid: KID.toLowerCase() }),
      retireInput({ requester: { kind: 'break_glass', operatingSystemUser: 'root' } }),
      retireInput({ nonce: newOperationNonce() }),
    ].map((each) => operationDigest(keyRetirementOperation(each)).toString('hex'));
    expect(others).not.toContain(base);
    expect(new Set(others).size).toBe(others.length);
    // No rotation of the same realm hashes to a retirement's digest.
    expect(others).not.toContain(operationDigest(keyRotationOperation(input())).toString('hex'));
  });

  it('hashes only the members of a record, whatever else the object carries', () => {
    const record = keyRetirementOperation(retireInput());
    const padded = {
      ...record,
      purpose: 'token_signing',
      requester: { ...record.requester, extra: 'x' },
    } as unknown as KeyRetirementOperationRecord;
    expect(canonicalOperationBytes(padded)).toEqual(canonicalOperationBytes(record));
  });

  it.each([
    ['a realm id that is not a UUID', retireInput({ realmId: 'realm-1' })],
    ['an empty kid', retireInput({ kid: '' })],
    ['a kid over the length limit', retireInput({ kid: 'k'.repeat(MAX_KID_LENGTH + 1) })],
    ['a kid with a control character', retireInput({ kid: 'kid\n' })],
    ['a kid with a lone surrogate', retireInput({ kid: 'kid\ud800' })],
    ['a kid that is no text', retireInput({ kid: 42 as never })],
    ['a requester of no known kind', retireInput({ requester: { kind: 'robot' } as never })],
    ['a short nonce', retireInput({ nonce: NONCE.slice(0, 40) })],
  ])('refuses %s', (_name, value) => {
    expect(() => keyRetirementOperation(value)).toThrow(TypeError);
  });

  it('reads a kid of at most 255 characters', () => {
    expect(isKid(KID)).toBe(true);
    expect(isKid('k'.repeat(MAX_KID_LENGTH))).toBe(true);
    expect(isKid(' ')).toBe(true);
    expect(isKid(undefined)).toBe(false);
  });
});

describe('checking an approval before an operation reads anything', () => {
  const approval = {
    id: '0190D7A2-6F4E-7C1A-9B3E-5A8D2C4F6EBB',
    operation: KEK_ROTATE_OPERATION,
    requester: ADMIN,
    nonce: NONCE,
    consume: async () => undefined,
  };

  it('copies the members it reads, with the id in lower case', () => {
    const checked = checkedApproval(approval, KEK_ROTATE_OPERATION, 'needs one');
    expect(checked).toMatchObject({
      id: '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6ebb',
      requester: ADMIN,
      nonce: NONCE,
    });
    expect(Object.isFrozen(checked)).toBe(true);
  });

  it.each([
    ['no approval', undefined, 'missing'],
    [
      'an approval of another operation',
      { ...approval, operation: KEY_ROTATE_OPERATION },
      'other_operation',
    ],
    ['an approval without an operation', { ...approval, operation: undefined }, 'malformed'],
    ['an id that is no UUID', { ...approval, id: 'approval-1' }, 'malformed'],
    ['no consume', { ...approval, consume: undefined }, 'malformed'],
  ])('refuses %s', (_name, value, reason) => {
    const error = (() => {
      try {
        checkedApproval(value, KEK_ROTATE_OPERATION, 'A KEK rotation needs an approval');
      } catch (caught) {
        return caught;
      }
      return undefined;
    })();
    expect(error).toBeInstanceOf(OperationApprovalError);
    expect(error).toMatchObject({ reason });
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
