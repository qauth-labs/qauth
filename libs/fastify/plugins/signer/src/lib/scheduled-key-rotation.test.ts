import { canonicalizeJson } from '@qauth-labs/infra-db';
import {
  canonicalOperationBytes,
  keyRotationOperation,
  type KeyRotationOperationInput,
  newOperationNonce,
} from '@qauth-labs/server-keys';
import { describe, expect, it } from 'vitest';

/**
 * The canonical record of a manual rotation (#544) is hashed over its RFC
 * 8785 form. The key library writes that form itself, as it may not import
 * the database layer; the approval it is bound to is stored beside the admin
 * audit log, whose canonicalizer is the database layer's. Both must write the
 * same bytes for the same record.
 */
describe('the canonical record of a manual rotation', () => {
  const nonce = newOperationNonce();
  const inputs: readonly KeyRotationOperationInput[] = [
    {
      realmId: '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e01',
      purpose: 'token_signing',
      requester: {
        kind: 'human',
        realmId: '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e00',
        accountId: '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6eaa',
      },
      nonce,
    },
    {
      realmId: '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e01',
      purpose: 'webhook_signing',
      scopeId: 'sub "quoted" \\ é \u2028 😀',
      requester: { kind: 'break_glass', operatingSystemUser: 'qauth-ops' },
      nonce,
    },
  ];

  it.each(inputs)('is the RFC 8785 form the admin audit canonicalizer writes (%#)', (input) => {
    const record = keyRotationOperation(input);
    expect(canonicalOperationBytes(record).toString('utf8')).toBe(canonicalizeJson(record));
  });
});
