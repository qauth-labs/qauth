import type { AdminOperationDefinition } from '../../helpers/admin-operations';

/**
 * SEALING A SECRET FOR A SECURITY OPERATION (ADR-019 Decision 7, issue #984).
 *
 * A security operation that sets a secret takes it only sealed: its
 * definition declares the members of its body that carry one
 * (`secretMembers`), and each takes `{ "sealed": "v1.…" }`, never the value.
 * `secrets.seal` makes that value: it encrypts a secret with the realm's
 * `data_at_rest` key, bound to one operation and one of its declared members,
 * and answers the ciphertext. It changes nothing and records no value, so it
 * is a write with no effect, under `secrets.seal`; the security operation
 * that then sets the value still needs its own permission and its approval.
 *
 * The approval that binds such a request, and the digest it is bound by,
 * hold a ciphertext: no guess of the secret can be tested against them.
 */

/** The ids of the operations that seal a secret. */
export const SECRET_OPERATION_IDS = Object.freeze({
  seal: 'secrets.seal',
} as const);

/** The definitions, for `ADMIN_OPERATIONS` (`helpers/admin-operations.ts`). */
export const SECRET_OPERATION_DEFINITIONS: readonly AdminOperationDefinition[] = Object.freeze([
  {
    id: SECRET_OPERATION_IDS.seal,
    class: 'write',
    effects: [],
    permissions: ['secrets.seal'],
    description:
      "Seal a value for one secret member of a security operation in a realm: it changes nothing, and answers the value encrypted for that operation, member and realm, which that operation's request then carries.",
  },
]);
