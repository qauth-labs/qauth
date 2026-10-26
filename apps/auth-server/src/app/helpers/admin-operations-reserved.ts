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
 * An entry names what the operation does and where the requirement comes
 * from. The ids follow the API conventions (`<resource>.<verb>`). The issue
 * that adds an operation may rename its entry before 1.0.0, in the same pull
 * request and visibly; it may not weaken it. The docs page
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
   * `classify` (a policy patch that only changes a token lifespan is a
   * write). Absent: every request needs the declaration.
   */
  readonly requestDependent?: true;
  /** Where the requirement comes from: a record's section or an issue. */
  readonly source: string;
  /** What the operation does, in one sentence. */
  readonly description: string;
}

const reserve = (
  id: string,
  effects: readonly SecurityEffect[],
  source: string,
  description: string
): ReservedOperation =>
  Object.freeze({ id, effects: Object.freeze([...effects]), source, description });

/** An entry whose request decides what the operation needs: it may `classify`. */
const reserveRequestDependent = (
  id: string,
  effects: readonly SecurityEffect[],
  source: string,
  description: string
): ReservedOperation =>
  Object.freeze({ ...reserve(id, effects, source, description), requestDependent: true as const });

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
    'Change realm policies: the mail transport and sender, the sign-in, password and brute-force policy, the registration policy, the environment ceiling and the two-admin set.'
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
    'Change a client: its redirect URIs, authentication method, first-party trust, verified domain, PKCE or DPoP, environment or agent-type fields.'
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
    'Apply a realm-file import or a sandbox promotion.'
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
