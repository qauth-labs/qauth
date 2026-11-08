import { describe, expect, it } from 'vitest';

import { PERMISSION_REGISTRY } from '../helpers/admin-permissions';
import {
  changePreview,
  changePreviewSchema,
  type PreviewedChange,
  scopesOf,
} from './change-preview';

/**
 * The preview shape every admin preview answers (#589): what it says of a
 * save, its secrets masked whatever it is handed.
 */

const WRITE = { class: 'write' as const, effects: [], permissions: ['realms.policies.write'] };
const SECURITY = {
  class: 'security' as const,
  effects: ['credential-path' as const],
  permissions: ['realms.policies.security'],
};

const change = (overrides: Partial<PreviewedChange> = {}): PreviewedChange => ({
  path: 'password.minScore',
  before: 3,
  after: 1,
  direction: 'loosening',
  classification: SECURITY,
  secret: false,
  environmentBound: false,
  ...overrides,
});

describe('the change preview (#589)', () => {
  it('names the scopes of the permissions, in the order of the scopes', () => {
    expect(
      scopesOf(
        ['realms.policies.security', 'realms.read', 'realms.policies.write'],
        PERMISSION_REGISTRY
      )
    ).toEqual(['qauth:admin:read', 'qauth:admin:write', 'qauth:admin:security']);
    expect(scopesOf([], PERMISSION_REGISTRY)).toEqual([]);
    expect(() => scopesOf(['realms.unknown'], PERMISSION_REGISTRY)).toThrow('not in the catalog');
  });

  it('says a security save needs an approval, and names it', () => {
    const preview = changePreview(
      {
        etag: '"4"',
        classification: {
          class: 'security',
          effects: ['credential-path'],
          permissions: ['realms.read', 'realms.policies.security'],
        },
        changes: [change()],
        approval: { twoAdmin: 'recommended', eligibleApprovers: 0 },
      },
      PERMISSION_REGISTRY
    );
    expect(preview).toMatchObject({
      approvalRequired: true,
      twoAdmin: 'recommended',
      eligibleApprovers: 0,
      scopes: ['qauth:admin:read', 'qauth:admin:security'],
    });
    expect(changePreviewSchema.parse(preview)).toEqual(preview);
  });

  it('masks a secret field whatever values it is handed', () => {
    const preview = changePreview(
      {
        etag: '"4"',
        classification: { ...SECURITY, permissions: ['realms.read', ...SECURITY.permissions] },
        changes: [
          change({ path: 'mail.smtp.password', before: true, after: 'hunter2', secret: true }),
          change({ path: 'mail.resend.apiKey', before: 'key', after: false, secret: true }),
        ],
        approval: { twoAdmin: 'recommended', eligibleApprovers: 2 },
      },
      PERMISSION_REGISTRY
    );
    expect(preview.changes.map(({ before, after }) => [before, after])).toEqual([
      ['set', 'not set'],
      ['not set', 'not set'],
    ]);
    expect(JSON.stringify(preview)).not.toMatch(/hunter2|"key"/);
  });

  it('refuses an approval for a write, none for a security save, and a read', () => {
    const build =
      (
        classification:
          | typeof WRITE
          | typeof SECURITY
          | { class: 'read'; effects: []; permissions: string[] },
        approval: { twoAdmin: 'recommended'; eligibleApprovers: number } | null
      ) =>
      () =>
        changePreview({ etag: '"1"', classification, changes: [], approval }, PERMISSION_REGISTRY);
    expect(build(WRITE, { twoAdmin: 'recommended', eligibleApprovers: 1 })).toThrow(
      'exactly when the save is a security save'
    );
    expect(build(SECURITY, null)).toThrow('exactly when the save is a security save');
    expect(build({ class: 'read', effects: [], permissions: ['realms.read'] }, null)).toThrow(
      'never a read'
    );
    expect(build(WRITE, null)()).toMatchObject({
      class: 'write',
      approvalRequired: false,
      twoAdmin: null,
      eligibleApprovers: null,
      changes: [],
    });
  });
});
