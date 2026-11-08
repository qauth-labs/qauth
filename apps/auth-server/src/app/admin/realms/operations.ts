import {
  diffPolicyPatch,
  type PolicyChange,
  type PolicyPatchDiff,
  PolicyValidationError,
  REALM_POLICY_REGISTRY,
} from '@qauth-labs/fastify-plugin-realm-policy';
import { NotFoundError } from '@qauth-labs/shared-errors';
import type { FastifyRequest } from 'fastify';

// Values from the classification module, never from the registry, which
// imports this one: see `helpers/admin-classification.ts`.
import {
  classifyByField,
  type FieldRule,
  mergePatchLeafPaths,
  UnknownFieldError,
} from '../../helpers/admin-classification';
import type {
  AdminOperationDefinition,
  Classification,
  ClassifyInput,
  RenderedField,
  RenderInput,
} from '../../helpers/admin-operations';
import { UnprocessableContentError } from '../../helpers/api-request-errors';
import {
  REALM_POLICIES_REFUSED_MESSAGE,
  unprocessablePolicyField,
} from '../../helpers/realm-policy-update';

/**
 * THE REALM OPERATIONS OF THE ADMIN API (ADR-019 Decisions 7 and 10, issue
 * #517): read a realm, and change its policies. They are the reference for
 * every later admin operation (`docs-site/.../reference/admin-operations.md`):
 * a permission in the catalog (`helpers/admin-permissions.ts`), a definition
 * here, its classification, its renderer, and the audit record its handler
 * keeps (`./routes.ts`).
 *
 * `realms.get` is a read (`realms.read`). `realms.policies.update` patches the
 * policies with a JSON Merge Patch and needs what its change needs, field by
 * field, as the policy annotations say (CFG-02, `@qauth-labs/server-realm-policy`):
 * a change the field's annotation makes a security change (on any change, or
 * when it loosens) needs `realms.policies.security`, so `qauth:admin:security`
 * and an approval, with the field's effects; any other needs
 * `realms.policies.write`. A patch of both needs both, and one approval.
 *
 * The change is judged on the merged document, never on the patch's members
 * alone (review of #890): `null` gives a field its default, which may be
 * looser than the stored value. A secret field is a security change whatever
 * the patch does with it, and only sealed (#984): its members are the
 * `secretMembers` below.
 */

/** The ids of the realm operations. */
export const REALM_OPERATION_IDS = Object.freeze({
  get: 'realms.get',
  updatePolicies: 'realms.policies.update',
} as const);

/**
 * What `realms.policies.update` classifies a patch against, as its
 * `loadState` reads it: the realm's policies in the realm representation's
 * view, each secret field as `<name>Set`, and the counter they were read at.
 */
export interface RealmPolicyState {
  /** The policies' counter (`policies_version`): the realm's `ETag`. */
  readonly version: number;
  /** The `representation` view of the policies: never a secret's value. */
  readonly policies: Readonly<Record<string, unknown>>;
}

/** The secret fields of the realm policies, as the registry names them. */
const SECRET_FIELDS = REALM_POLICY_REGISTRY.fields().filter((entry) => entry.field.secret);

/** A JSON Pointer token (RFC 6901). */
const pointerToken = (key: string): string => key.replace(/~/g, '~0').replace(/\//g, '~1');

/** The JSON Pointer of a field's segments in the policies, and so in a patch body. */
const pointerOf = (segments: readonly string[]): string =>
  segments.map((segment) => `/${pointerToken(segment)}`).join('');

/**
 * The members of a patch body that carry a secret (#984): each secret field
 * of the registry, as a JSON Pointer. The route's body schema holds each to
 * the sealed-value schema, and the handler opens it for this operation only.
 */
export const REALM_POLICY_SECRET_MEMBERS: readonly string[] = Object.freeze(
  SECRET_FIELDS.map((entry) => pointerOf(entry.segments))
);

/** The value at `segments` in `root`, or `undefined`. */
function valueAt(root: unknown, segments: readonly string[]): unknown {
  let node: unknown = root;
  for (const segment of segments) {
    if (typeof node !== 'object' || node === null || !Object.hasOwn(node, segment)) {
      return undefined;
    }
    node = (node as Record<string, unknown>)[segment];
  }
  return node;
}

/** The `<name>Set` flag of a secret field, beside it. */
const flagSegments = (segments: readonly string[]): string[] => [
  ...segments.slice(0, -1),
  `${segments[segments.length - 1]}Set`,
];

/** The secret fields whose representation `policies` shows as set. */
export function setSecretsOf(policies: unknown): string[] {
  return SECRET_FIELDS.filter(
    (entry) => valueAt(policies, flagSegments(entry.segments)) === true
  ).map((entry) => entry.path);
}

/** The secret fields a patch body sets or clears: every one it names. */
export function secretMembersNamed(body: unknown): string[] {
  return SECRET_FIELDS.filter((entry) => valueAt(body, entry.segments) !== undefined).map(
    (entry) => entry.path
  );
}

/**
 * The changes `body`, a merge patch of the realm policies, makes to `state`,
 * judged on the merged document. A secret member is a change whatever it
 * holds (a sealed value, or `null`), and is never opened here.
 *
 * @throws PolicyValidationError when the patch names a member the policies do
 *   not have, or the merged document is not valid
 */
export function policyPatchDiff(body: unknown, state: RealmPolicyState): PolicyPatchDiff {
  // The representation's `<name>Set` flags are dropped by the `input` view:
  // what remains is the stored document.
  const before = REALM_POLICY_REGISTRY.parse(state.policies, 'input');
  return diffPolicyPatch(before, body, { setSecrets: setSecretsOf(state.policies) });
}

/** What a request that changes nothing, or a change that is a write, needs. */
const WRITE: Classification = Object.freeze({
  class: 'write',
  effects: Object.freeze([]),
  permissions: Object.freeze(['realms.policies.write']),
});

/** What one changed field needs: its annotation decides (CFG-02). */
function classificationOfChange(change: PolicyChange): Classification {
  return change.class === 'security'
    ? { class: 'security', effects: [...change.effects], permissions: ['realms.policies.security'] }
    : WRITE;
}

/**
 * The classification of a policy patch (API-03). The fields it changes are
 * the leaf paths of its body (`mergePatchLeafPaths`), so a member the table
 * does not hold fails the request closed; each is classified by its change in
 * the merged document. A change the leaves do not account for (a group set
 * to `null`, which the route refuses anyway) fails it closed too.
 */
export function classifyPolicyPatch(
  request: ClassifyInput,
  state: RealmPolicyState
): Classification {
  const diff = policyPatchDiff(request.body, state);
  const leaves = new Set(mergePatchLeafPaths(request.body));
  const byPath = new Map(diff.changes.map((change) => [change.path, change]));
  const fields: Record<string, FieldRule<RealmPolicyState>> = {};
  for (const entry of REALM_POLICY_REGISTRY.fields()) {
    const pointer = pointerOf(entry.segments);
    const change = byPath.get(entry.path);
    const rule = change === undefined ? WRITE : classificationOfChange(change);
    fields[pointer] = rule;
    if (entry.field.secret) {
      // A sealed value is `{ sealed }`, whose one member is a leaf too; the
      // flag the representation shows sets and clears nothing.
      fields[`${pointer}/sealed`] = rule;
      fields[pointerOf(flagSegments(entry.segments))] = WRITE;
    }
  }
  for (const change of diff.changes) {
    const pointer = pointerOf(change.path.split('.'));
    if (!leaves.has(pointer) && !leaves.has(`${pointer}/sealed`)) {
      throw new UnknownFieldError(change.path);
    }
  }
  return classifyByField<RealmPolicyState>({
    changedFields: () => leaves,
    fields,
    unchanged: WRITE,
  })(request, state);
}

/**
 * The state `realms.policies.update` classifies against: the realm's policies
 * as its representation shows them, read through the policy store. On a
 * server without a secret store (#529) nothing can set a secret, so each
 * shows as not set, and a patch that names one is refused.
 *
 * @throws NotFoundError when the realm is gone
 */
export async function readPolicyState(
  request: FastifyRequest,
  realmId: string,
  tx?: Parameters<FastifyRequest['server']['policyStore']['get']>[1]
): Promise<RealmPolicyState & { readonly schemaVersion: string }> {
  const { policyStore, realmSecretStore } = request.server;
  if (realmSecretStore === null) {
    const snapshot = await policyStore.get(realmId, tx);
    if (snapshot === undefined) throw new NotFoundError('Realm', realmId);
    return {
      version: snapshot.version,
      schemaVersion: snapshot.schemaVersion,
      policies: REALM_POLICY_REGISTRY.toRepresentation(snapshot.policies, []),
    };
  }
  const representation = await policyStore.representation(realmId, tx);
  if (representation === undefined) throw new NotFoundError('Realm', realmId);
  return {
    version: representation.version,
    schemaVersion: representation.schemaVersion,
    policies: representation.policies,
  };
}

/**
 * `realms.policies.update`'s `loadState`: the realm's policies, once the
 * patch is checked against them. A patch whose merged document the policy
 * schema refuses is answered 422 here, before it is classified or authorized
 * further, and is never filed for an approval: the fields it names are what
 * it would change, and there is no change to approve. So is one that sets or
 * clears a secret on a server with no secret store.
 *
 * @throws UnprocessableContentError naming each refused field
 */
async function loadPolicyState(
  request: FastifyRequest,
  input: ClassifyInput
): Promise<RealmPolicyState> {
  // The realm the authority stage resolved; read off the pipeline's state,
  // not through the pipeline module, which imports the registry.
  const caller = request.adminPipeline?.authority;
  if (caller === undefined) {
    throw new Error('realms.policies.update reads its realm only behind the admin pipeline');
  }
  const state = await readPolicyState(request, caller.targetRealm.id);
  if (request.server.realmSecretStore === null) {
    const named = secretMembersNamed(input.body);
    if (named.length > 0) {
      throw new UnprocessableContentError(
        named.map((path) =>
          unprocessablePolicyField({
            path,
            message: 'is a secret, and this server has no secret store to keep it in',
          })
        ),
        REALM_POLICIES_REFUSED_MESSAGE
      );
    }
  }
  try {
    policyPatchDiff(input.body, state);
  } catch (error) {
    if (error instanceof PolicyValidationError) {
      throw new UnprocessableContentError(
        error.issues.map(unprocessablePolicyField),
        REALM_POLICIES_REFUSED_MESSAGE
      );
    }
    throw error;
  }
  return state;
}

/** The longest value an approver is shown, before the display caps it. */
const MAX_RENDERED_VALUE = 500;

/** A policy value as an approver reads it: JSON, capped. */
function shownValue(value: unknown): string {
  const text = JSON.stringify(value) ?? 'null';
  return text.length > MAX_RENDERED_VALUE ? `${text.slice(0, MAX_RENDERED_VALUE)}…` : text;
}

/** The most changed fields one approval shows, under the display's cap of 50 lines. */
const MAX_RENDERED_CHANGES = 48;

/** One changed field, side by side; a secret by whether it is set, never by a value. */
function renderedChange(change: PolicyChange): RenderedField {
  if (change.secret) {
    return {
      label: change.path,
      before: change.before === true ? 'set (not shown)' : 'not set',
      value: change.after === true ? 'set to a new sealed value (not shown)' : 'cleared',
    };
  }
  return { label: change.path, before: shownValue(change.before), value: shownValue(change.after) };
}

/**
 * What an approver is shown of a policy patch (#517): each field it changes,
 * the stored value beside the new one, judged on the merged document against
 * the policies the approval was filed against (`RenderInput.state`). A secret
 * shows only whether it was set and whether the patch sets or clears it.
 */
function renderPolicyPatch(input: RenderInput) {
  const state = input.state as RealmPolicyState | undefined;
  if (state === undefined) {
    throw new Error('A policy patch is shown against the policies it was filed against');
  }
  const diff = policyPatchDiff(input.body, state);
  const shown = diff.changes.slice(0, MAX_RENDERED_CHANGES);
  const fields: RenderedField[] = [
    { label: 'replaces the policies of version', value: String(state.version) },
    ...shown.map(renderedChange),
  ];
  if (diff.changes.length > shown.length) {
    fields.push({
      label: 'and more',
      value: `${diff.changes.length - shown.length} more changed fields, not shown`,
    });
  }
  return {
    title:
      diff.changes.length === 1
        ? 'Change one realm policy'
        : `Change ${diff.changes.length} realm policies`,
    fields,
  };
}

/** Every effect any policy field has: what `realms.policies.update` declares, at most. */
const POLICY_EFFECTS = [
  ...new Set(REALM_POLICY_REGISTRY.fields().flatMap((entry) => entry.field.effects)),
];

/**
 * The definitions, for `ADMIN_OPERATIONS` (`helpers/admin-operations.ts`).
 * `realms.policies.update` declares the reserved effects of its entry
 * (`admin-operations-reserved.ts`) and every effect a policy field has, so a
 * group another area registers later is within its declaration.
 */
export const REALM_OPERATION_DEFINITIONS: readonly AdminOperationDefinition[] = Object.freeze([
  {
    id: REALM_OPERATION_IDS.get,
    class: 'read',
    effects: [],
    permissions: ['realms.read'],
    description:
      'Read a realm: its name, whether it is enabled and the operator realm, its times, and its policies, each secret field only as whether it is set.',
  },
  {
    id: REALM_OPERATION_IDS.updatePolicies,
    class: 'security',
    effects: [
      ...new Set([
        'credential-path',
        'token-content',
        'posture-loosening',
        'administration',
        ...POLICY_EFFECTS,
      ] as const),
    ],
    permissions: ['realms.policies.write', 'realms.policies.security'],
    description:
      "Change a realm's policies with a JSON Merge Patch against the version it names; each field it changes needs what its annotation says, a security change an approval, and a secret field only sealed.",
    loadState: loadPolicyState,
    stateVersion: (state: unknown) => String((state as RealmPolicyState).version),
    classify: (request: ClassifyInput, state: unknown) =>
      classifyPolicyPatch(request, state as RealmPolicyState),
    render: renderPolicyPatch,
    secretMembers: REALM_POLICY_SECRET_MEMBERS,
  } as AdminOperationDefinition,
]);
