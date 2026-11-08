import {
  defaultsFromEnv,
  REALM_POLICY_REGISTRY,
  toRealmPoliciesRepresentation,
} from '@qauth-labs/fastify-plugin-realm-policy';
import { describe, expect, it } from 'vitest';

import {
  classifyRequest,
  mergeClassifications,
  OPERATION_REGISTRY,
  operationStateVersion,
} from '../../helpers/admin-operations';
import { RESERVED_OPERATIONS } from '../../helpers/admin-operations-reserved';
import { changePreview } from '../change-preview';
import { policyPatchDiff, REALM_OPERATION_IDS, type RealmPolicyState } from './operations';
import { previewPolicyPatch } from './preview';

/**
 * The preview of a policy patch (#589) against the update it previews: for
 * every fixture, the preview and `realms.policies.update` classify the patch
 * the same way and find the same changes. The fixtures are the security
 * cases the reserved table holds for the update (`admin-operations-reserved.ts`)
 * and the writes, no-ops and mixed patches below. The same comparison over
 * the real routes, against real containers, is in
 * `admin-realm-policy-preview.integration.test.ts`.
 */

const REALM = '00000000-0000-4000-8000-000000000001';

/** A value as secrets.seal answers one. */
const SEALED = 'v1.kid-1.aXZhaXZhaXZhaXZh.Y2lwaGVydGV4dGNpcGhlcnRleHQ';

const update = () => {
  const found = OPERATION_REGISTRY.get(REALM_OPERATION_IDS.updatePolicies);
  if (found === undefined) throw new Error('realms.policies.update is not registered');
  return found;
};

const reserved = RESERVED_OPERATIONS.find((entry) => entry.id === 'realms.policies.update');

/** The state the reserved cases meet: tightened policies, the SMTP password set. */
const STATE = reserved?.vectors?.[0]?.state as RealmPolicyState;

/** The writes, no-ops and mixed patches, against {@link STATE}. */
const MORE_FIXTURES: readonly { readonly name: string; readonly body: Record<string, unknown> }[] =
  [
    { name: 'raises the password minimum length', body: { password: { minLength: 20 } } },
    {
      name: 'shortens the access-token lifetime',
      body: { tokens: { accessTokenLifespanSeconds: 300 } },
    },
    {
      name: 'lengthens the lockout',
      body: { bruteForce: { lockoutSeconds: 1800 } },
    },
    {
      name: 'loosens a field no change of which is a security change',
      body: { mail: { invalidateExistingTokensOnResend: false } },
    },
    { name: 'changes nothing', body: {} },
    { name: 'sends a stored value back', body: { password: { minLength: 15 } } },
    {
      name: 'mixes a write and a security change',
      body: { tokens: { accessTokenLifespanSeconds: 300 }, password: { minScore: 1 } },
    },
    {
      name: 'adds an operation to the two-admin set',
      body: { admin: { twoAdminMandatoryOperations: ['keys.rotate', 'realms.policies.update'] } },
    },
    {
      name: 'sets the SMTP password again',
      body: { mail: { smtp: { password: { sealed: SEALED } } } },
    },
    {
      name: 'sends the representation flag of a secret back',
      body: { mail: { smtp: { passwordSet: true } } },
    },
  ];

const FIXTURES = [
  ...(reserved?.vectors ?? []).map((vector) => ({
    name: vector.name,
    body: vector.request.body as Record<string, unknown>,
  })),
  ...MORE_FIXTURES,
];

/** The patch as the pipeline classifies `realms.policies.update` with it. */
function updateClassification(body: unknown, state: RealmPolicyState = STATE) {
  const operation = update();
  return classifyRequest(
    OPERATION_REGISTRY,
    operation,
    { method: 'PATCH', params: { realmId: REALM }, query: {}, body },
    state,
    operationStateVersion(operation, state)
  );
}

describe('the policy preview against the update it previews (#589)', () => {
  it('has fixtures: every security case of the reserved table and the patches above', () => {
    expect(reserved?.vectors?.length).toBeGreaterThanOrEqual(10);
    expect(STATE.version).toBe(7);
  });

  // Acceptance criterion of #589: for every fixture, the preview and the real
  // update classify the same way.
  it.each(FIXTURES)('classifies "$name" as the update does', ({ body }) => {
    const preview = previewPolicyPatch(OPERATION_REGISTRY, REALM, body, STATE);
    const classified = updateClassification(body);
    expect(preview.classification).toEqual(classified);
    expect(preview.classification.failedClosed).toBeNull();
    // The update's own classify, as its definition holds it.
    const own = update().classify?.(
      { method: 'PATCH', params: { realmId: REALM }, query: {}, body },
      STATE
    );
    expect({
      class: preview.classification.class,
      effects: [...preview.classification.effects].sort(),
      permissions: [...preview.classification.permissions].sort(),
    }).toEqual({
      class: own?.class,
      effects: [...(own?.effects ?? [])].sort(),
      permissions: [...(own?.permissions ?? [])].sort(),
    });
  });

  it.each(FIXTURES)('finds the changes of "$name" the update finds', ({ body }) => {
    const preview = previewPolicyPatch(OPERATION_REGISTRY, REALM, body, STATE);
    const diff = policyPatchDiff(body, STATE);
    expect(preview.changes.map((change) => change.path)).toEqual(
      diff.changes.map((change) => change.path)
    );
    expect(preview.changes.map((change) => change.direction)).toEqual(
      diff.changes.map((change) => change.direction)
    );
    // The fields' classifications, with the read every patch needs, are the
    // patch's.
    const merged = mergeClassifications([
      { class: 'read', effects: [], permissions: ['realms.read'] },
      { class: 'write', effects: [], permissions: ['realms.policies.write'] },
      ...preview.changes.map((change) => change.classification),
    ]);
    const security = preview.classification.class === 'security';
    expect(merged.class).toBe(preview.classification.class);
    expect([...merged.effects].sort()).toEqual([...preview.classification.effects].sort());
    // A security-only patch needs no write permission; a write needs it.
    const permissions = new Set(preview.classification.permissions);
    for (const change of preview.changes) {
      for (const permission of change.classification.permissions) {
        expect(permissions.has(permission), permission).toBe(true);
      }
    }
    expect(permissions.has('realms.read')).toBe(true);
    expect(security).toBe(
      preview.changes.some((change) => change.classification.class === 'security')
    );
  });

  it('marks a loosening a security change, with its direction, effects and scopes', () => {
    const preview = previewPolicyPatch(
      OPERATION_REGISTRY,
      REALM,
      { password: { minScore: 1 } },
      STATE
    );
    const answer = changePreview(
      {
        etag: '"7"',
        classification: preview.classification,
        changes: preview.changes,
        approval: { twoAdmin: 'recommended', eligibleApprovers: 1 },
      },
      OPERATION_REGISTRY.permissions
    );
    expect(answer).toEqual({
      etag: '"7"',
      class: 'security',
      effects: ['credential-path'],
      permissions: ['realms.policies.security', 'realms.read'],
      scopes: ['qauth:admin:read', 'qauth:admin:security'],
      approvalRequired: true,
      twoAdmin: 'recommended',
      eligibleApprovers: 1,
      changes: [
        {
          path: 'password.minScore',
          before: 3,
          after: 1,
          direction: 'loosening',
          class: 'security',
          effects: ['credential-path'],
          permissions: ['realms.policies.security'],
          scopes: ['qauth:admin:security'],
          secret: false,
          environmentBound: false,
        },
      ],
    });
  });

  it('marks a tightening a write, which needs no approval', () => {
    const preview = previewPolicyPatch(
      OPERATION_REGISTRY,
      REALM,
      { tokens: { accessTokenLifespanSeconds: 300 } },
      STATE
    );
    const answer = changePreview(
      {
        etag: '"7"',
        classification: preview.classification,
        changes: preview.changes,
        approval: null,
      },
      OPERATION_REGISTRY.permissions
    );
    expect(answer).toMatchObject({
      class: 'write',
      effects: [],
      scopes: ['qauth:admin:read', 'qauth:admin:write'],
      approvalRequired: false,
      twoAdmin: null,
      eligibleApprovers: null,
      changes: [
        {
          path: 'tokens.accessTokenLifespanSeconds',
          before: 900,
          after: 300,
          direction: 'tightening',
          class: 'write',
          effects: [],
          scopes: ['qauth:admin:write'],
        },
      ],
    });
  });

  it('judges null by the default it gives the field, as the update does', () => {
    const preview = previewPolicyPatch(
      OPERATION_REGISTRY,
      REALM,
      { registration: { cimd: { trustPolicy: null } } },
      STATE
    );
    expect(preview.changes).toEqual([
      expect.objectContaining({
        path: 'registration.cimd.trustPolicy',
        before: 'allowlist',
        after: REALM_POLICY_REGISTRY.field('registration.cimd.trustPolicy')?.field.default,
        direction: 'loosening',
        classification: expect.objectContaining({ class: 'security' }),
      }),
    ]);
  });

  // Acceptance criterion of #589: a secret field never appears in the
  // answer, only whether it is set.
  it('shows a secret only as set or not set, never its sealed value', () => {
    const notSet = {
      version: 2,
      policies: toRealmPoliciesRepresentation(defaultsFromEnv({}), []),
    } satisfies RealmPolicyState;
    const cases = [
      [STATE, { password: { sealed: SEALED } }, 'set', 'set'],
      [STATE, { password: null }, 'set', 'not set'],
      [notSet, { password: { sealed: SEALED } }, 'not set', 'set'],
      [notSet, { password: null }, 'not set', 'not set'],
    ] as const;
    for (const [state, smtp, before, after] of cases) {
      const preview = previewPolicyPatch(OPERATION_REGISTRY, REALM, { mail: { smtp } }, state);
      const answer = changePreview(
        {
          etag: `"${state.version}"`,
          classification: preview.classification,
          changes: preview.changes,
          approval: { twoAdmin: 'recommended', eligibleApprovers: 0 },
        },
        OPERATION_REGISTRY.permissions
      );
      expect(answer.changes).toEqual([
        expect.objectContaining({
          path: 'mail.smtp.password',
          before,
          after,
          secret: true,
          class: 'security',
          effects: ['credential-path'],
        }),
      ]);
      expect(JSON.stringify(answer)).not.toContain(SEALED);
      expect(JSON.stringify(answer)).not.toContain('sealed');
    }
  });

  it('refuses a patch the update refuses, and a registry without the update', () => {
    expect(() =>
      previewPolicyPatch(OPERATION_REGISTRY, REALM, { password: { minLength: 'long' } }, STATE)
    ).toThrow(expect.objectContaining({ name: 'PolicyValidationError' }));
    expect(() =>
      previewPolicyPatch({ ...OPERATION_REGISTRY, get: () => undefined }, REALM, {}, STATE)
    ).toThrow('holds no realms.policies.update');
  });
});
