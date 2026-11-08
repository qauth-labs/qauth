import { buildPasswordCredentialData } from '@qauth-labs/fastify-plugin-federation';
import { NotFoundError } from '@qauth-labs/shared-errors';
import { getEventType } from '@qauth-labs/shared-events';
import { OPERATOR_VERIFICATION_METHODS } from '@qauth-labs/shared-validation';
import type { FastifyRequest } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import { AccountVerificationConflictError } from '../../helpers/account-verification-errors';
import { OPERATION_REGISTRY } from '../../helpers/admin-operations';
import { RESERVED_OPERATIONS } from '../../helpers/admin-operations-reserved';
import type { AdminRateLimitCheck } from '../pipeline';
import {
  type AccountVerificationState,
  accountVerificationStateVersion,
  USER_OPERATION_IDS,
} from './operations';
import { accountVerificationOf, accountVerificationSchema } from './routes';

/**
 * The account operations of the admin API (#1052), without a listener: the
 * entry of `users.verify` in the registry, the account its `loadState` reads
 * and the version the approval binds, what an approver is shown, and the
 * route in the admin document. The route behind the pipeline, its approval
 * and its write are exercised against real containers in
 * `admin-users-verify.integration.test.ts`.
 */

const REALM = '018f2d6e-8a8b-7c3d-9e0f-1a2b3c4d5e6f';
const OTHER_REALM = '018f2d6e-8a8b-7c3d-9e0f-1a2b3c4d5e70';
const USER = '018f2d6e-8a8b-7c3d-9e0f-1a2b3c4d5e71';
const ADMIN = '018f2d6e-8a8b-7c3d-9e0f-1a2b3c4d5e72';

const operation = () => {
  const found = OPERATION_REGISTRY.get(USER_OPERATION_IDS.verify);
  if (found === undefined) throw new Error('users.verify is not registered');
  return found;
};

interface UserRow {
  id: string;
  enabled: boolean;
  createdAt: number;
  operatorVerifiedAt: number | null;
  operatorVerifiedBy: string | null;
}

const userRow = (overrides: Partial<UserRow> = {}): UserRow => ({
  id: USER,
  enabled: true,
  createdAt: Date.UTC(2026, 10, 1),
  operatorVerifiedAt: null,
  operatorVerifiedBy: null,
  ...overrides,
});

const credential = (overrides: Record<string, unknown>) => ({
  realmId: REALM,
  externalSub: 'ada@example.com',
  isPrimary: false,
  disabledAt: null,
  credentialData: {},
  ...overrides,
});

const PASSWORD = credential({
  id: 'c2',
  providerType: 'password',
  isPrimary: true,
  credentialData: buildPasswordCredentialData('$argon2id$h', false, 'nfc'),
});
const TOTP = credential({ id: 'c1', providerType: 'totp', externalSub: 'totp' });

/** A request behind the pipeline, for `users.verify`'s `loadState`. */
function requestFor(user: UserRow | undefined, rows: unknown[], transaction?: unknown) {
  return {
    adminPipeline: { authority: { targetRealm: { id: REALM } }, transaction },
    server: {
      repositories: {
        users: { findById: vi.fn(async () => user) },
        userCredentials: { findAllByUserId: vi.fn(async () => rows) },
      },
    },
  } as unknown as FastifyRequest & {
    server: {
      repositories: {
        users: { findById: ReturnType<typeof vi.fn> };
        userCredentials: { findAllByUserId: ReturnType<typeof vi.fn> };
      };
    };
  };
}

const verifyRequest = { method: 'POST', params: { realmId: REALM, userId: USER }, query: {} };

async function load(request: FastifyRequest): Promise<AccountVerificationState> {
  const loadState = operation().loadState;
  if (loadState === undefined) throw new Error('users.verify reads no state');
  return (await loadState(request, { ...verifyRequest, body: {} })) as AccountVerificationState;
}

describe('users.verify in the registry (#1052)', () => {
  it('is a security operation with the effect credential-path, needing users.security', () => {
    const verify = operation();
    expect([verify.id, verify.class, verify.effects, verify.permissions]).toEqual([
      'users.verify',
      'security',
      ['credential-path'],
      ['users.security'],
    ]);
    expect(OPERATION_REGISTRY.permissions.get('users.security')?.class).toBe('security');
    // Every request needs the declaration: nothing classifies it lower.
    expect(verify.classify).toBeUndefined();
    expect(verify.secretMembers).toBeUndefined();
  });

  it('takes the reserved entry, which no later change may file under qauth:admin:write', () => {
    const reserved = RESERVED_OPERATIONS.find((entry) => entry.id === 'users.verify');
    expect(reserved).toMatchObject({ effects: ['credential-path'] });
    expect(reserved?.requestDependent).toBeUndefined();
  });

  it('records the methods the user.verified event names, and the event takes each', () => {
    const type = getEventType('urn:qauth:event:user.verified:v1-rc.0');
    expect(type).toMatchObject({ category: 'admin', security: true });
    for (const method of OPERATOR_VERIFICATION_METHODS) {
      expect(type?.data.safeParse({ method }).success).toBe(true);
    }
    expect(type?.data.safeParse({ method: 'operator', email: 'ada@example.com' }).success).toBe(
      false
    );
  });
});

describe('the account users.verify meets (#1052)', () => {
  it("reads the account and its credentials in the realm, by id, with each one's proof", async () => {
    const foreign = credential({ id: 'c0', providerType: 'password', realmId: OTHER_REALM });
    const state = await load(requestFor(userRow(), [PASSWORD, foreign, TOTP]));
    expect(state).toEqual({
      userId: USER,
      createdAt: Date.UTC(2026, 10, 1),
      credentials: [
        {
          id: 'c1',
          type: 'totp',
          primary: false,
          disabled: false,
          proof: 'none',
          identifier: null,
        },
        {
          id: 'c2',
          type: 'password',
          primary: true,
          disabled: false,
          proof: 'not_proved',
          identifier: 'ada@example.com',
        },
      ],
    });
  });

  it('shows an upstream identity as vouched for by its provider, and a confirmed address as proved', async () => {
    const upstream = credential({
      id: 'c3',
      providerType: 'oidc_corp',
      externalSub: 'sub-1',
      credentialData: { kind: 'upstream', iss: 'https://idp.example.com', verified: true },
    });
    const confirmed = credential({
      id: 'c4',
      providerType: 'password',
      credentialData: buildPasswordCredentialData('$argon2id$h', true, 'nfc'),
    });
    const state = await load(requestFor(userRow(), [upstream, confirmed]));
    expect(state.credentials.map((entry) => [entry.id, entry.proof, entry.identifier])).toEqual([
      ['c3', 'provider', null],
      ['c4', 'proved', 'ada@example.com'],
    ]);
  });

  it('refuses an account the realm does not hold with 404', async () => {
    await expect(load(requestFor(undefined, []))).rejects.toBeInstanceOf(NotFoundError);
  });

  it('refuses a disabled account, and one an operator already verified, with 409', async () => {
    const disabled = await load(requestFor(userRow({ enabled: false }), [])).catch(
      (error: unknown) => error
    );
    expect(disabled).toBeInstanceOf(AccountVerificationConflictError);
    expect(disabled).toMatchObject({ statusCode: 409, refusal: 'disabled' });
    const verified = await load(
      requestFor(userRow({ operatorVerifiedAt: 1, operatorVerifiedBy: 'operator_cli' }), [])
    ).catch((error: unknown) => error);
    expect(verified).toMatchObject({ statusCode: 409, refusal: 'already_verified' });
  });

  // As realms.policies.update's (#887): inside a handler, as when
  // approvals.create files the verification, the read holds no second
  // connection beside the handler's transaction.
  it("reads in the handler's transaction when it runs inside one", async () => {
    const tx = { id: 'handler-tx' };
    const outside = requestFor(userRow(), []);
    await load(outside);
    expect(outside.server.repositories.users.findById).toHaveBeenCalledWith(REALM, USER, undefined);
    const inside = requestFor(userRow(), [], tx);
    await load(inside);
    expect(inside.server.repositories.users.findById).toHaveBeenCalledWith(REALM, USER, tx);
    expect(inside.server.repositories.userCredentials.findAllByUserId).toHaveBeenCalledWith(
      USER,
      tx
    );
  });

  it('versions the state as an entity-tag value that changes with any credential', async () => {
    const before = await load(requestFor(userRow(), [PASSWORD]));
    const again = await load(requestFor(userRow(), [PASSWORD]));
    const added = await load(requestFor(userRow(), [PASSWORD, TOTP]));
    const version = operation().stateVersion?.(before);
    expect(version).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(accountVerificationStateVersion(again)).toBe(version);
    expect(accountVerificationStateVersion(added)).not.toBe(version);
  });
});

describe('what an approver is shown of a verification (#1052)', () => {
  const render = (state?: AccountVerificationState) => {
    const { render: renderer } = operation();
    if (renderer === undefined) throw new Error('users.verify has no renderer');
    return renderer({
      operationId: USER_OPERATION_IDS.verify,
      ...verifyRequest,
      body: {},
      state,
    });
  };

  it('shows the account, that it is unclaimed and claimed by this, and each credential with its proof', async () => {
    const state = await load(requestFor(userRow(), [PASSWORD, TOTP]));
    const rendered = render(state);
    expect(rendered.title).toBe('Verify an account as the operator');
    const fields = Object.fromEntries(
      (rendered.fields ?? []).map((field) => [field.label, field.value])
    );
    expect(fields['account']).toBe(USER);
    expect(fields['created']).toBe('2026-11-01T00:00:00.000Z');
    expect(fields['now']).toContain('unclaimed and this claims it');
    expect(fields['effect']).toContain('email_verified is not changed');
    expect(fields['effect']).toContain('claims the account if it is unclaimed');
    expect(fields['credential password (primary)']).toBe('address ada@example.com not confirmed');
    expect(fields['credential totp']).toBe('proves no identity');
  });

  it('says an account with no credential has none, and caps a long list under the display limit', async () => {
    const none = render(await load(requestFor(userRow(), [])));
    expect(none.fields).toContainEqual({ label: 'credentials', value: 'none' });
    const many = Array.from({ length: 45 }, (_, index) =>
      credential({ id: `k${String(index).padStart(2, '0')}`, providerType: 'webauthn' })
    );
    const capped = render(await load(requestFor(userRow(), many)));
    expect(capped.fields?.length).toBeLessThanOrEqual(50);
    expect(capped.fields?.at(-1)).toEqual({
      label: 'and more',
      value: '5 more credentials, not shown',
    });
  });

  it('refuses to render without the account the approval was filed against', () => {
    expect(() => render(undefined)).toThrow(/filed against/);
  });
});

describe('the verification the route answers (#1052)', () => {
  it("names the admin for users.verify and the host's user for the command", () => {
    const at = Date.UTC(2026, 10, 8, 12);
    expect(
      accountVerificationOf({
        id: USER,
        operatorVerifiedAt: at,
        operatorVerifiedBy: `operator:${ADMIN}`,
      })
    ).toEqual({
      userId: USER,
      verifiedAt: '2026-11-08T12:00:00.000Z',
      method: 'operator',
      verifiedBy: ADMIN,
    });
    const cli = accountVerificationOf({
      id: USER,
      operatorVerifiedAt: at,
      operatorVerifiedBy: 'operator_cli',
    });
    expect(cli).toMatchObject({ method: 'operator_cli', verifiedBy: null });
    expect(accountVerificationSchema.safeParse(cli).success).toBe(true);
  });

  it('refuses an account with no verification of a known form', () => {
    expect(() =>
      accountVerificationOf({ id: USER, operatorVerifiedAt: null, operatorVerifiedBy: null })
    ).toThrow();
    expect(() =>
      accountVerificationOf({ id: USER, operatorVerifiedAt: 1, operatorVerifiedBy: 'someone' })
    ).toThrow();
  });
});

describe('the account routes in the admin OpenAPI document (#1052)', () => {
  it("pass the API conventions against the server's own registry", async () => {
    const [{ default: Fastify }, { default: swagger }, zod, { adminOpenapiOptions }, pipeline] =
      await Promise.all([
        import('fastify'),
        import('@fastify/swagger'),
        import('fastify-type-provider-zod'),
        import('../openapi-options'),
        import('../pipeline'),
      ]);
    const { checkApiConventions } = await import('../../api-conventions/openapi-conventions');
    const { userRoutes } = await import('./routes');

    const app = Fastify({ logger: false });
    try {
      app.setValidatorCompiler(zod.validatorCompiler);
      app.setSerializerCompiler(zod.serializerCompiler);
      await app.register(swagger, adminOpenapiOptions);
      const uncounted: AdminRateLimitCheck = async () => ({ isAllowed: true, key: 'uncounted' });
      await app.register(pipeline.adminPipeline, {
        registry: OPERATION_REGISTRY,
        refusalsByAddress: uncounted,
        callsBySubject: uncounted,
        routes: async (scope) => {
          await scope.register(userRoutes);
        },
      });
      await app.ready();

      const document = app.swagger() as unknown as {
        paths: Record<string, Record<string, Record<string, unknown>>>;
      };
      expect(Object.keys(document.paths)).toEqual([
        '/admin/v1-rc.0/realms/{realmId}/users/{userId}/verification',
      ]);
      const verify =
        document.paths['/admin/v1-rc.0/realms/{realmId}/users/{userId}/verification']['post'];
      expect(verify).toMatchObject({
        operationId: 'users.verify',
        'x-qauth-class': 'security',
        'x-qauth-permission': 'users.security',
        'x-qauth-effects': ['credential-path'],
      });
      expect(JSON.stringify(verify['requestBody'])).toContain('AdminAccountVerificationRequest');
      expect(JSON.stringify(verify['responses'])).toContain('AdminAccountVerification');
      const report = checkApiConventions(document, { operations: OPERATION_REGISTRY });
      expect(report.violations).toEqual([]);
      expect(report.checkedOperations).toBe(1);
    } finally {
      await app.close();
    }
  });
});
