import {
  defaultsFromEnv,
  toRealmPoliciesRepresentation,
} from '@qauth-labs/fastify-plugin-realm-policy';
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
 * taken by a `classify` that answers `write`. A merge-patch operation MUST
 * derive the fields a request changes with `mergePatchLeafPaths(body)`, which
 * walks the body's own keys (an array is one field, a `null` member is a
 * change), and classify them with `classifyByField`, which throws on a field
 * its table does not hold: only then does an unknown field fail closed. A
 * `classify` that reads only the fields it expects never sees the others. By effect (ADR-019 Decision 7), lengthening an access-token,
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

/**
 * A realm's policies, as the policy cases meet them: the state
 * `realms.policies.update` reads (#517), its policies in the realm
 * representation's view (each secret as `<name>Set`), with values a loosening
 * can be measured against. Built from the defaults, so the cases follow the
 * schema the release ships.
 */
const REALM_POLICIES = (() => {
  const document = defaultsFromEnv({}) as unknown as Record<string, Record<string, unknown>>;
  document['password'] = { ...document['password'], minLength: 15, minScore: 3 };
  document['bruteForce'] = { ...document['bruteForce'], enabled: true, lockoutSeconds: 900 };
  document['tokens'] = {
    ...document['tokens'],
    accessTokenLifespanSeconds: 900,
    refreshTokenLifespanSeconds: 604800,
  };
  document['posture'] = { ...document['posture'], maxEnvironmentLaxity: 'production' };
  document['registration'] = {
    ...document['registration'],
    dynamicRegistrationAllowedScopes: ['openid'],
    cimd: {
      ...(document['registration']['cimd'] as Record<string, unknown>),
      trustPolicy: 'allowlist',
      trustedDomains: ['clients.example'],
    },
  };
  document['admin'] = { ...document['admin'], twoAdminMandatoryOperations: ['keys.rotate'] };
  return {
    version: 7,
    policies: toRealmPoliciesRepresentation(document, ['mail.smtp.password']),
  };
})();

/**
 * A client, as the client cases meet it: the state `clients.update` reads
 * (#632), in the admin API's client representation
 * (`admin/clients/representation.ts`), a first-party candidate no developer
 * owns, so every case can be measured against it.
 */
const CLIENT_STATE = {
  id: CLIENT.clientId,
  client_id: 'app',
  name: 'App',
  description: null,
  developerId: null,
  provisionedByOperator: true,
  dynamicallyRegistered: false,
  metadataDocument: null,
  enabled: true,
  suspended: false,
  suspendedAt: null,
  redirectUris: ['https://app.example/callback'],
  postLogoutRedirectUris: ['https://app.example/signed-out'],
  backchannelLogoutUri: null,
  backchannelLogoutUriSource: null,
  backchannelLogoutSessionRequired: false,
  scopes: ['openid', 'notes:read'],
  clientCredentialsScopes: null,
  grantTypes: ['authorization_code', 'refresh_token'],
  responseTypes: ['code'],
  tokenEndpointAuthMethod: 'private_key_jwt',
  jwks: {
    keys: [{ kty: 'OKP', crv: 'Ed25519', x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU' }],
  },
  jwksUri: null,
  requirePkce: true,
  dpopBoundAccessTokens: true,
  environment: 'production',
  isAgent: false,
  maxAgentMode: null,
  verifiedDomain: null,
  firstPartyProfile: null,
  firstPartyPolicy: null,
  firstPartyReason: null,
  accessTokenLifespanSeconds: 300,
  refreshTokenLifespanSeconds: 86400,
  createdAt: '2026-11-01T00:00:00.000Z',
  updatedAt: '2026-11-01T00:00:00.000Z',
  lastUsedAt: null,
};

/** A client that obtains admin tokens: one holding a `qauth:admin:*` scope. */
const ADMIN_CLIENT_STATE = {
  ...CLIENT_STATE,
  client_id: 'console',
  scopes: ['openid', 'qauth:admin:read', 'qauth:admin:security'],
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
    'users.verify',
    ['credential-path'],
    `${ADR_019}, ADR-015 Decision 8, #1052, #682`,
    "Verify an account as the operator: it counts as verified for sign-in and for owning an agent, and an unclaimed account is claimed, so another person's mailbox proof no longer ends it."
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
      // The cases of this entry, in the representation #517 ships. Five
      // cases of the first guess name fields no policy group has yet: the
      // session lifetime (lengthened, and its cap removed), the key rotation
      // interval, and audit-event retention (shortened, and switched off),
      // which the realm row holds outside the policies. The issue that
      // registers each field adds its case back here.
      policyCase('lowers the password minimum length', { password: { minLength: 8 } }, [
        'credential-path',
      ]),
      policyCase('lowers the password score', { password: { minScore: 1 } }, ['credential-path']),
      policyCase('switches brute-force protection off', { bruteForce: { enabled: false } }, [
        'credential-path',
      ]),
      policyCase('shortens the lockout', { bruteForce: { lockoutSeconds: 60 } }, [
        'credential-path',
      ]),
      policyCase('lets anyone sign up', { accounts: { allowSignUp: true } }, ['credential-path']),
      policyCase('lengthens the new-factor window', { accounts: { newFactorWindowDays: 30 } }, [
        'credential-path',
      ]),
      policyCase('shortens the new-factor window', { accounts: { newFactorWindowDays: 1 } }, [
        'credential-path',
      ]),
      policyCase(
        'raises the environment ceiling',
        { posture: { maxEnvironmentLaxity: 'development' } },
        ['posture-loosening']
      ),
      policyCase(
        'lengthens the access-token lifetime',
        { tokens: { accessTokenLifespanSeconds: 3600 } },
        ['posture-loosening']
      ),
      policyCase(
        'lengthens the refresh-token lifetime',
        { tokens: { refreshTokenLifespanSeconds: 2592000 } },
        ['posture-loosening']
      ),
      policyCase(
        'gives a field its looser default',
        { registration: { cimd: { trustPolicy: null } } },
        ['token-content']
      ),
      policyCase(
        'widens the scopes dynamic registration allows',
        { registration: { dynamicRegistrationAllowedScopes: ['openid', 'offline_access'] } },
        ['token-content']
      ),
      policyCase('changes the mail transport', { mail: { provider: 'resend' } }, [
        'credential-path',
      ]),
      policyCase(
        'sets the SMTP password',
        { mail: { smtp: { password: { sealed: 'v1.k.aXY.Y2lwaGVydGV4dA' } } } },
        ['credential-path']
      ),
      policyCase('clears the SMTP password', { mail: { smtp: { password: null } } }, [
        'credential-path',
      ]),
      policyCase('changes the two-admin set', { admin: { twoAdminMandatoryOperations: [] } }, [
        'administration',
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
    ['token-content', 'posture-loosening', 'administration'],
    `${ADR_019}, #518, #632`,
    "Change a client: its redirect URIs, post-logout redirect URIs, back-channel logout URI, authentication method and keys, grant types, first-party trust, verified domain, PKCE or DPoP, client_credentials scopes, qauth: scopes, environment, token lifetimes or agent-type fields; lengthening a client's token lifetime or switching PKCE or DPoP off is posture-loosening; any change of a client that obtains admin tokens is administration.",
    [
      clientCase(
        'adds a redirect URI',
        { redirectUris: ['https://app.example/callback', 'https://other.example/callback'] },
        ['token-content']
      ),
      // OpenID Connect RP-Initiated Logout 1.0 §3.1 (#675): no token goes
      // there, but a new entry widens where the end-session route sends the
      // browser.
      clientCase(
        'adds a post-logout redirect URI',
        {
          postLogoutRedirectUris: [
            'https://app.example/signed-out',
            'https://other.example/signed-out',
          ],
        },
        ['posture-loosening']
      ),
      // OpenID Connect Back-Channel Logout 1.0 §2.2 (#624): a logout token
      // naming the user and the session goes there, and a URI an admin sets
      // may reach a destination the egress allowlist opens.
      clientCase(
        'sets a back-channel logout URI',
        { backchannelLogoutUri: 'https://app.example/backchannel' },
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
      // ADR-017 Decision 2 (#631): the first guess's `firstParty: true`, as
      // the representation #632 ships names first-party trust.
      clientCase(
        'makes the client first-party',
        { firstPartyProfile: 'web_redirect', firstPartyReason: 'The operator runs the app.' },
        ['token-content']
      ),
      {
        name: 'removes first-party trust',
        request: patch(CLIENT, { firstPartyProfile: null }),
        state: {
          ...CLIENT_STATE,
          firstPartyProfile: 'web_redirect',
          firstPartyReason: 'The operator runs the app.',
        },
        effects: ['token-content'],
      },
      // ADR-019 Decision 6 (#593): the domain every screen shows first for the
      // client, above the name it declares.
      clientCase('sets the verified domain', { verifiedDomain: 'app.example' }, ['token-content']),
      {
        name: 'changes the verified domain',
        request: patch(CLIENT, { verifiedDomain: 'other.example' }),
        state: { ...CLIENT_STATE, verifiedDomain: 'app.example' },
        effects: ['token-content'],
      },
      // #891: the scopes a token that names no user may carry.
      {
        name: 'lifts the client_credentials scope list',
        request: patch(CLIENT, { clientCredentialsScopes: null }),
        state: { ...CLIENT_STATE, clientCredentialsScopes: ['ssf:stream'] },
        effects: ['token-content'],
      },
      {
        name: 'widens the client_credentials scope list',
        request: patch(CLIENT, { clientCredentialsScopes: ['ssf:stream', 'notes:read'] }),
        state: { ...CLIENT_STATE, clientCredentialsScopes: ['ssf:stream'] },
        effects: ['token-content'],
      },
      clientCase('loosens the environment', { environment: 'development' }, ['posture-loosening']),
      // Cases #632 adds, in the representation it ships.
      clientCase(
        'adds a grant type',
        { grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'] },
        ['token-content']
      ),
      clientCase('makes the client an agent', { isAgent: true }, ['token-content']),
      clientCase('gives an agent a mode', { maxAgentMode: 'exec' }, ['token-content']),
      clientCase(
        'adds a scope of the qauth: namespace',
        { scopes: ['openid', 'notes:read', 'qauth:admin:read'] },
        ['token-content']
      ),
      clientCase('lengthens the access-token lifetime', { accessTokenLifespanSeconds: 600 }, [
        'posture-loosening',
      ]),
      clientCase(
        "gives the refresh-token lifetime back to the realm's",
        { refreshTokenLifespanSeconds: null },
        ['posture-loosening']
      ),
      // A client_credentials client with no list of its own is issued any
      // scope it holds (#891): a scope added is a scope its tokens carry.
      {
        name: 'adds a scope to a client_credentials client without a list',
        request: patch(CLIENT, { scopes: ['notes:read', 'notes:write'] }),
        state: {
          ...CLIENT_STATE,
          grantTypes: ['client_credentials'],
          responseTypes: [],
          redirectUris: [],
          postLogoutRedirectUris: [],
          scopes: ['notes:read'],
        },
        effects: ['token-content'],
      },
      // A client that obtains admin tokens administers the realm: renaming
      // it, as any other change, is shown to a second admin.
      {
        name: 'renames a client that obtains admin tokens',
        request: patch(CLIENT, { name: 'Console' }),
        state: ADMIN_CLIENT_STATE,
        effects: ['administration'],
      },
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
  reserveRequestDependent(
    'clients.disable',
    ['administration'],
    `${ADR_019}, #632`,
    'Suspend a client. Suspending one that obtains admin tokens takes the admin API from whoever signs in through it.',
    [
      {
        name: 'suspends a client that obtains admin tokens',
        request: { method: 'POST', params: CLIENT, query: {}, body: {} },
        state: ADMIN_CLIENT_STATE,
        effects: ['administration'],
      },
    ]
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
