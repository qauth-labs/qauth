import type { SecurityEffect } from '@qauth-labs/shared-validation';

/**
 * The reserved operation ids (issue #508): for each effect of ADR-019
 * Decision 7, the admin operations other areas register later, with the
 * effects each must carry.
 *
 * The admin API has no such operation yet. When one is registered
 * (`createOperationRegistry` in `admin-operations.ts`), the registry refuses
 * it unless it is a security operation whose effects include every effect
 * listed here, so no later change files one of them under
 * `qauth:admin:write`, and an id that differs from one only in case is
 * refused. An operation may carry more effects than its entry. Only an entry
 * marked `requestDependent` (a policy patch, a client update, an import) may
 * `classify`: such an operation declares every effect and lets `classify`
 * pick per request. Every other reserved operation needs its declaration on
 * every request.
 *
 * A request-dependent entry lists security cases (`vectors`): a request and
 * the state it meets, with the effects the request needs at least. The
 * registry runs the operation's `classify` on each at boot and refuses it
 * when it gives a case less, or fails closed on it, so the entry cannot be
 * taken by a `classify` that answers `write`. A merge-patch operation derives
 * the fields a request changes with `mergePatchLeafPaths(body)`, which walks
 * the body's own keys (an array is one field, a `null` member is a change),
 * and classifies them with `classifyByField`, which fails an unknown field
 * closed. By effect (ADR-019 Decision 7), lengthening an access-token,
 * refresh-token or session lifetime or the key rotation interval, and
 * shortening or switching off audit-event retention, are `posture-loosening`;
 * shortening a lifetime or lengthening retention is a write.
 *
 * An entry names what the operation does and where the requirement comes
 * from. The ids follow the API conventions (`<resource>.<verb>`). The issue
 * that adds an operation may rename its entry before 1.0.0, in the same pull
 * request and visibly; it may not weaken it. It writes its entry's vectors in
 * the representation it ships (their field names are this table's guess), in
 * the same way, and may add cases but not drop one or lower its effects. The docs page
 * `reference/security-operations.md` lists the table, grouped by effect.
 *
 * Not reserved, on purpose: sending a set-up or reset link to the contact
 * address already on the account (it reaches only whom a self-service reset
 * reaches), brand strings and links (display data under `qauth:admin:write`),
 * and the developer and account APIs, which keep their own rules (ADR-012,
 * ADR-017). The realm-file import's dry run (#518) is a read; its apply step
 * is reserved below.
 */
export interface ReservedOperation {
  /** The operation id the operation registers under. */
  readonly id: string;
  /** The effects it must carry, at least. */
  readonly effects: readonly SecurityEffect[];
  /**
   * `true` when the request decides what the operation needs, so it may
   * `classify` (a policy patch that only shortens a token lifetime is a
   * write). Absent: every request needs the declaration.
   */
  readonly requestDependent?: true;
  /**
   * With `requestDependent`, the security cases its `classify` must meet;
   * one or more. Absent otherwise.
   */
  readonly vectors?: readonly ReservedVector[];
  /** Where the requirement comes from: a record's section or an issue. */
  readonly source: string;
  /** What the operation does, in one sentence. */
  readonly description: string;
}

/**
 * A security case of a request-dependent entry: a request, the state it
 * meets, and the effects it needs at least. Its classification must be
 * `security` with every one of `effects`.
 */
export interface ReservedVector {
  /** What the request does, in a few words. */
  readonly name: string;
  /** The request as `classify` sees it. */
  readonly request: {
    readonly method: string;
    readonly params: unknown;
    readonly query: unknown;
    readonly body: unknown;
  };
  /** The state `loadState` returns, in the admin API's representation of the resource. */
  readonly state: unknown;
  /** The effects the request needs at least: some of its entry's. */
  readonly effects: readonly SecurityEffect[];
}

/** `value`, frozen with everything it holds. */
function frozen<T>(value: T): T {
  if (typeof value === 'object' && value !== null && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const key of Reflect.ownKeys(value)) {
      frozen((value as Record<PropertyKey, unknown>)[key]);
    }
  }
  return value;
}

const reserve = (
  id: string,
  effects: readonly SecurityEffect[],
  source: string,
  description: string
): ReservedOperation =>
  Object.freeze({ id, effects: Object.freeze([...effects]), source, description });

/** An entry whose request decides what the operation needs: it may `classify`, and must meet `vectors`. */
const reserveRequestDependent = (
  id: string,
  effects: readonly SecurityEffect[],
  source: string,
  description: string,
  vectors: readonly ReservedVector[]
): ReservedOperation =>
  Object.freeze({
    ...reserve(id, effects, source, description),
    requestDependent: true as const,
    vectors: frozen([...vectors]),
  });

/** A merge patch of the resource at `params`, as `classify` sees it. */
const patch = (params: Record<string, string>, body: Record<string, unknown>) => ({
  method: 'PATCH',
  params,
  query: {},
  body,
});

const REALM = { realmId: '00000000-0000-4000-8000-000000000001' };
const CLIENT = { ...REALM, clientId: '00000000-0000-4000-8000-000000000002' };

/** A realm's policies, as the policy cases meet them. */
const REALM_POLICIES = {
  accessTokenLifespan: 900,
  refreshTokenLifespan: 604800,
  ssoMaxLifespan: 86400,
  ssoIdleTimeout: 1800,
  keyRotationIntervalDays: 90,
  adminEventRetentionDays: 365,
  userEventRetentionDays: 90,
  maxEnvironmentLaxity: 'production',
  passwordPolicy: { minLength: 12 },
  bruteForce: { enabled: true, maxFailures: 5 },
};

/** A client, as the client cases meet it. */
const CLIENT_STATE = {
  redirectUris: ['https://app.example/callback'],
  tokenEndpointAuthMethod: 'private_key_jwt',
  jwks: {
    keys: [{ kty: 'OKP', crv: 'Ed25519', x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU' }],
  },
  jwksUri: null,
  requirePkce: true,
  dpopBoundAccessTokens: true,
  firstParty: false,
  environment: 'production',
};

const policyCase = (
  name: string,
  body: Record<string, unknown>,
  effects: readonly SecurityEffect[]
): ReservedVector => ({ name, request: patch(REALM, body), state: REALM_POLICIES, effects });

const clientCase = (
  name: string,
  body: Record<string, unknown>,
  effects: readonly SecurityEffect[]
): ReservedVector => ({ name, request: patch(CLIENT, body), state: CLIENT_STATE, effects });

/** A realm file applied over `REALM_IMPORT_STATE`. */
const REALM_IMPORT_STATE = {
  displayName: 'Example',
  passwordPolicy: { minLength: 12 },
  clients: [{ clientId: 'app', redirectUris: ['https://app.example/callback'] }],
};

const importCase = (name: string, file: Record<string, unknown>): ReservedVector => ({
  name,
  request: { method: 'POST', params: REALM, query: {}, body: { ...REALM_IMPORT_STATE, ...file } },
  state: REALM_IMPORT_STATE,
  effects: ['import'],
});

const ADR_019 = 'ADR-019 Decision 7';
const ADR_020 = 'ADR-020 §3';

/** The table, grouped by the effect each entry exists for. */
export const RESERVED_OPERATIONS: readonly ReservedOperation[] = Object.freeze([
  // credential-path: which credentials, links or addresses can authenticate or
  // recover an account.
  reserve(
    'users.links.copy',
    ['credential-path'],
    `${ADR_019}, ${ADR_020}`,
    'Copy a one-time set-up or reset link, returned once to the admin who copies it.'
  ),
  reserve(
    'users.identifiers.update',
    ['credential-path'],
    `${ADR_019}, ${ADR_020}`,
    "Change an account's identifier or contact address."
  ),
  reserve(
    'users.password.set',
    ['credential-path'],
    `${ADR_019}, ${ADR_020}`,
    "Set an account's password."
  ),
  reserve(
    'users.passkeys.create',
    ['credential-path'],
    `${ADR_019}, ${ADR_020}`,
    'Add a passkey to an account.'
  ),
  reserve(
    'users.credentials.create',
    ['credential-path'],
    `${ADR_019}, ${ADR_020}`,
    'Add any other credential to an account, such as a TOTP secret or an upstream identity.'
  ),
  reserve(
    'users.passkeys.delete',
    ['credential-path'],
    `${ADR_019}, ${ADR_020}`,
    'Remove a passkey from an account.'
  ),
  reserve(
    'users.totp.delete',
    ['credential-path'],
    `${ADR_019}, ${ADR_020}`,
    "Remove an account's TOTP."
  ),
  reserve(
    'users.recoveryCodes.delete',
    ['credential-path'],
    ADR_019,
    "Remove an account's recovery codes."
  ),
  reserve(
    'users.linkedAccounts.delete',
    ['credential-path'],
    ADR_019,
    'Unlink an upstream or wallet account from an account.'
  ),
  reserve(
    'users.idJagSubjects.create',
    ['credential-path'],
    `${ADR_019}, ADR-011 gate 14`,
    'Link an enterprise ID-JAG subject to an account, the one link an admin may make.'
  ),
  reserve(
    'upstreamProviders.create',
    ['credential-path'],
    `${ADR_019}, #714`,
    'Add an upstream identity provider.'
  ),
  reserve(
    'upstreamProviders.update',
    ['credential-path'],
    `${ADR_019}, #714`,
    'Change an upstream identity provider.'
  ),
  reserve(
    'upstreamProviders.disable',
    ['credential-path'],
    `${ADR_019}, #714`,
    'Disable an upstream identity provider.'
  ),
  reserve(
    'upstreamProviders.delete',
    ['credential-path'],
    `${ADR_019}, #714`,
    'Remove an upstream identity provider.'
  ),
  reserve(
    'upstreamProviders.mappers.create',
    ['credential-path'],
    `${ADR_019}, #714`,
    "Add a mapper to an upstream provider's claims."
  ),
  reserve(
    'upstreamProviders.mappers.update',
    ['credential-path'],
    `${ADR_019}, #714`,
    "Change a mapper of an upstream provider's claims."
  ),
  reserve(
    'upstreamProviders.mappers.delete',
    ['credential-path'],
    `${ADR_019}, #714`,
    "Remove a mapper of an upstream provider's claims."
  ),
  reserve(
    'trustedIssuers.create',
    ['credential-path'],
    ADR_019,
    'Trust a credential issuer for wallet sign-in.'
  ),
  reserve(
    'trustedIssuers.update',
    ['credential-path'],
    ADR_019,
    'Change a trusted credential issuer.'
  ),
  reserve(
    'trustedIssuers.delete',
    ['credential-path'],
    ADR_019,
    'Stop trusting a credential issuer.'
  ),
  reserve(
    'plugins.enable',
    ['credential-path'],
    `${ADR_019}, #600`,
    'Enable an AuthMethod plugin in a realm.'
  ),
  reserve(
    'plugins.update',
    ['credential-path'],
    `${ADR_019}, #600`,
    "Change an AuthMethod plugin's configuration in a realm."
  ),
  reserveRequestDependent(
    'realms.policies.update',
    ['credential-path', 'token-content', 'posture-loosening', 'administration'],
    `${ADR_019}, #514, #517`,
    'Change realm policies: the mail transport and sender, the sign-in, password and brute-force policy, the registration policy, the environment ceiling, token and session lifetimes, the key rotation interval, audit-event retention and the two-admin set; lengthening a lifetime or the rotation interval, or shortening or switching off retention, is posture-loosening.',
    [
      policyCase('lowers the password minimum length', { passwordPolicy: { minLength: 8 } }, [
        'credential-path',
      ]),
      policyCase('switches brute-force protection off', { bruteForce: { enabled: false } }, [
        'credential-path',
      ]),
      policyCase('raises the environment ceiling', { maxEnvironmentLaxity: 'development' }, [
        'posture-loosening',
      ]),
      policyCase('lengthens the access-token lifetime', { accessTokenLifespan: 3600 }, [
        'posture-loosening',
      ]),
      policyCase('lengthens the refresh-token lifetime', { refreshTokenLifespan: 2592000 }, [
        'posture-loosening',
      ]),
      policyCase('lengthens the session lifetime', { ssoMaxLifespan: 604800 }, [
        'posture-loosening',
      ]),
      policyCase('removes the session lifetime cap', { ssoMaxLifespan: null }, [
        'posture-loosening',
      ]),
      policyCase('lengthens the key rotation interval', { keyRotationIntervalDays: 365 }, [
        'posture-loosening',
      ]),
      policyCase('shortens audit-event retention', { adminEventRetentionDays: 90 }, [
        'posture-loosening',
      ]),
      policyCase('switches audit-event retention off', { adminEventRetentionDays: null }, [
        'posture-loosening',
      ]),
    ]
  ),

  // token-content: what a token asserts or who receives it.
  reserve(
    'clients.create',
    ['token-content'],
    `${ADR_019}, #518, #632`,
    'Register a client, with its redirect URIs, authentication method and trust.'
  ),
  reserveRequestDependent(
    'clients.update',
    ['token-content', 'posture-loosening'],
    `${ADR_019}, #518, #632`,
    'Change a client: its redirect URIs, authentication method, first-party trust, verified domain, PKCE or DPoP, environment or agent-type fields.',
    [
      clientCase(
        'adds a redirect URI',
        { redirectUris: ['https://app.example/callback', 'https://other.example/callback'] },
        ['token-content']
      ),
      clientCase(
        'sets the token endpoint authentication method to none',
        {
          tokenEndpointAuthMethod: 'none',
        },
        ['token-content']
      ),
      clientCase('replaces the JWKS', { jwks: { keys: [] } }, ['token-content']),
      clientCase(
        'moves the keys to a JWKS URI',
        { jwks: null, jwksUri: 'https://keys.example/jwks.json' },
        ['token-content']
      ),
      clientCase('switches PKCE off', { requirePkce: false }, ['posture-loosening']),
      clientCase('switches DPoP binding off', { dpopBoundAccessTokens: false }, [
        'posture-loosening',
      ]),
      clientCase('makes the client first-party', { firstParty: true }, ['token-content']),
      clientCase('loosens the environment', { environment: 'development' }, ['posture-loosening']),
    ]
  ),
  reserve(
    'clients.secret.rotate',
    ['token-content'],
    `${ADR_019}, #518`,
    "Rotate a client's secret, returned once to the admin who rotates it."
  ),
  reserve(
    'clients.registrationToken.rotate',
    ['token-content'],
    `${ADR_019}, #518`,
    "Rotate a client's registration access token (RFC 7592), returned once to the admin who rotates it."
  ),
  reserve('clients.delete', ['token-content'], `${ADR_019}, #518, #632`, 'Delete a client.'),
  reserve(
    'scopes.create',
    ['token-content'],
    `${ADR_019}, ${ADR_020}`,
    'Add a scope to the catalog.'
  ),
  reserve(
    'scopes.update',
    ['token-content'],
    `${ADR_019}, ${ADR_020}`,
    'Change a scope of the catalog.'
  ),
  reserve(
    'scopes.delete',
    ['token-content'],
    `${ADR_019}, ${ADR_020}`,
    'Remove a scope from the catalog.'
  ),
  reserve('mappers.create', ['token-content'], ADR_019, 'Add a token mapper.'),
  reserve('mappers.update', ['token-content'], ADR_019, 'Change a token mapper.'),
  reserve('mappers.delete', ['token-content'], ADR_019, 'Remove a token mapper.'),
  reserve(
    'resourceServers.create',
    ['token-content'],
    ADR_019,
    'Register a resource server and its audience.'
  ),
  reserve(
    'resourceServers.update',
    ['token-content'],
    ADR_019,
    'Change a resource server or its audience.'
  ),
  reserve(
    'resourceServers.delete',
    ['token-content'],
    ADR_019,
    'Remove a resource server and its audience.'
  ),
  reserve('roles.create', ['token-content'], `${ADR_019}, #683`, 'Define a realm role.'),
  reserve(
    'roles.update',
    ['token-content'],
    `${ADR_019}, #683`,
    'Change a realm role, its name or composites.'
  ),
  reserve('roles.delete', ['token-content'], `${ADR_019}, #683`, 'Delete a realm role.'),
  reserve('groups.create', ['token-content'], `${ADR_019}, #683`, 'Define a group.'),
  reserve('groups.update', ['token-content'], `${ADR_019}, #683`, 'Change a group.'),
  reserve('groups.delete', ['token-content'], `${ADR_019}, #683`, 'Delete a group.'),
  reserve(
    'groups.roles.assign',
    ['token-content'],
    `${ADR_019}, #683`,
    "Map a realm role to a group, so the group's members hold it."
  ),
  reserve(
    'groups.roles.remove',
    ['token-content'],
    `${ADR_019}, #683`,
    'Remove a realm role from a group.'
  ),
  reserve(
    'users.roles.assign',
    ['token-content'],
    `${ADR_019}, #683`,
    'Assign a role to an account.'
  ),
  reserve(
    'users.roles.remove',
    ['token-content'],
    `${ADR_019}, #683`,
    'Remove a role from an account.'
  ),
  reserve(
    'groups.members.add',
    ['token-content'],
    `${ADR_019}, #683`,
    'Add an account to a group.'
  ),
  reserve(
    'groups.members.remove',
    ['token-content'],
    `${ADR_019}, #683`,
    'Remove an account from a group.'
  ),
  reserve('webhooks.create', ['token-content'], '#537', 'Add a webhook subscription.'),
  reserve('webhooks.update', ['token-content'], '#537', 'Change a webhook subscription.'),
  reserve('webhooks.delete', ['token-content'], '#537', 'Remove a webhook subscription.'),
  reserve(
    'webhooks.rotateSecret',
    ['token-content'],
    '#537',
    "Rotate a webhook subscription's signing secret."
  ),
  reserve(
    'webhooks.test',
    ['token-content'],
    '#537',
    "Send a test event to a webhook subscription's destination."
  ),
  reserve('ssfStreams.create', ['token-content'], '#537', 'Add a Shared Signals stream.'),
  reserve(
    'ssfStreams.update',
    ['token-content'],
    '#537',
    "Change a Shared Signals stream's destination."
  ),
  reserve('ssfStreams.delete', ['token-content'], '#537', 'Remove a Shared Signals stream.'),

  // issue-for-other: a token or session for someone other than the caller.
  reserve(
    'users.actChainTokens.create',
    ['issue-for-other'],
    `${ADR_019}, #523`,
    'Issue an act-chain token to an admin who acts for an account.'
  ),

  // administration: who administers.
  reserve('admins.create', ['administration'], `${ADR_019}, #679`, 'Create an admin account.'),
  reserve('admins.delete', ['administration'], `${ADR_019}, #679`, 'Remove an admin account.'),
  reserve(
    'adminGrants.create',
    ['administration'],
    `${ADR_019}, #679`,
    'Grant an admin role to an account in a realm.'
  ),
  reserve(
    'adminGrants.delete',
    ['administration'],
    `${ADR_019}, #679`,
    'Remove an admin role from an account.'
  ),
  reserve(
    'adminRoles.create',
    ['administration'],
    `${ADR_019}, #679`,
    'Create a custom admin role.'
  ),
  reserve(
    'adminRoles.update',
    ['administration'],
    `${ADR_019}, #679`,
    'Change the permissions of a custom admin role.'
  ),
  reserve(
    'adminRoles.delete',
    ['administration'],
    `${ADR_019}, #679`,
    'Delete a custom admin role.'
  ),
  reserve(
    'serviceAccounts.create',
    ['administration'],
    `${ADR_019}, #679`,
    'Create a service account for the admin API.'
  ),
  reserve(
    'serviceAccounts.delete',
    ['administration'],
    `${ADR_019}, #679`,
    'Remove a service account.'
  ),

  // import: a realm file, or a sandbox promotion, whose diff holds any other effect.
  reserveRequestDependent(
    'realms.imports.apply',
    ['import'],
    'ADR-019 Decisions 7 and 11, #531, #555',
    'Apply a realm-file import or a sandbox promotion.',
    [
      importCase('lowers the password policy', { passwordPolicy: { minLength: 6 } }),
      importCase('adds a redirect URI to a client', {
        clients: [
          {
            clientId: 'app',
            redirectUris: ['https://app.example/callback', 'https://other.example/callback'],
          },
        ],
      }),
    ]
  ),

  // federation-operator.
  reserve(
    'federation.entityConfiguration.update',
    ['federation-operator'],
    `${ADR_019}, ADR-020 §3`,
    "Change the realm's federation entity configuration and authority hints."
  ),
  reserve(
    'federation.subordinates.create',
    ['federation-operator'],
    `${ADR_019}, ADR-020 §3`,
    'Add a federation subordinate.'
  ),
  reserve(
    'federation.subordinates.update',
    ['federation-operator'],
    `${ADR_019}, ADR-020 §3`,
    'Change a federation subordinate.'
  ),
  reserve(
    'federation.subordinates.delete',
    ['federation-operator'],
    `${ADR_019}, ADR-020 §3`,
    'Remove a federation subordinate.'
  ),
  reserve(
    'federation.metadataPolicy.update',
    ['federation-operator'],
    `${ADR_019}, ADR-020 §3`,
    'Change the federation metadata policy and its constraints.'
  ),
  reserve(
    'federation.trustMarks.create',
    ['federation-operator'],
    `${ADR_019}, ADR-020 §3`,
    'Issue a trust mark.'
  ),
  reserve(
    'federation.trustMarks.delete',
    ['federation-operator'],
    `${ADR_019}, ADR-020 §3`,
    'Revoke a trust mark.'
  ),
  reserve(
    'federation.registrations.approve',
    ['federation-operator'],
    `${ADR_019}, #731`,
    'Approve an explicit federation registration.'
  ),
  reserve(
    'federation.keys.rotate',
    ['federation-operator', 'key-custody'],
    `${ADR_019}, ADR-020 §3`,
    'Rotate the federation keys.'
  ),

  // key-custody.
  reserve(
    'keys.rotate',
    ['key-custody'],
    'ADR-019 Decision 9, #544',
    "Rotate a realm's key before its rotation is due."
  ),
  reserve(
    'keys.retire',
    ['key-custody'],
    'ADR-019 Decision 9',
    'Retire a key, which leaves the JWKS at once.'
  ),
  reserve(
    'kek.rotate',
    ['key-custody'],
    'ADR-019 Decision 9, #545',
    'Rotate the KEK and re-wrap every stored key.'
  ),

  // realm-lifecycle.
  reserve('realms.delete', ['realm-lifecycle'], ADR_019, 'Delete a realm.'),
  reserve(
    'realms.ownership.transfer',
    ['realm-lifecycle'],
    ADR_019,
    "Transfer a realm's ownership."
  ),

  // authority-tree-power.
  reserve(
    'agents.revoke',
    ['authority-tree-power'],
    `${ADR_019}, ADR-014`,
    "Revoke by agent: end every grant and token of an agent's authority tree."
  ),
  reserve(
    'transmitters.disable',
    ['authority-tree-power'],
    `${ADR_019}, ADR-014`,
    'Disable a registered transmitter.'
  ),

  // posture-loosening: carried by realms.policies.update (the realm's
  // environment ceiling) and clients.update (a client's environment) above.

  // bulk-revocation.
  reserve(
    'clients.sessions.revokeAll',
    ['bulk-revocation'],
    `${ADR_020}, #625`,
    'Revoke every session and refresh-token family of a client.'
  ),
  reserve(
    'realms.sessions.revokeAll',
    ['bulk-revocation'],
    `${ADR_020}, #550`,
    'Revoke sessions of a realm in bulk.'
  ),
]);
