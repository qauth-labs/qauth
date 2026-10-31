import { REALM_POLICY_REGISTRY } from './realm-policies';
import type { PolicyRegistry } from './registry';

/**
 * Where a realm keeps the values of its secret policy fields (ADR-019
 * Decisions 9 and 10, issue #516), such as `mail.smtp.password`. A secret is
 * never in the policy document: not on the realm row, not in the admin API's
 * representation (which shows `<name>Set`), not in the realm file. The policy
 * store hands every secret a write sets or clears to this store, in the
 * write's transaction.
 *
 * This is the interface only. The store that implements it, encrypted with
 * the realm's data-at-rest key, comes with the realm mail settings (#529);
 * until a server has one, the policy store refuses every write that sets or
 * clears a secret.
 *
 * Every method takes a realm id and a secret field's path, as the registry
 * names it. An implementation refuses a path that is not a secret field
 * ({@link realmSecretPaths}), and never repeats a value in an error or a log.
 */
export interface RealmSecretStore<Tx = unknown> {
  /**
   * Set the secret at `path` to `value`, or clear it with `null`, in `tx`
   * when one is given: a policy update commits its document and its secrets
   * together, or neither.
   */
  put(realmId: string, path: string, value: string | null, tx?: Tx): Promise<void>;
  /** Whether the secret at `path` holds a value: what the representation shows as `<name>Set`. */
  isSet(realmId: string, path: string, tx?: Tx): Promise<boolean>;
  /**
   * The value of the secret at `path`, or `undefined` when it holds none, for
   * the one component that uses it (the realm's mail sender for the mail
   * secrets). Never for a response, a log, an audit record or an export.
   */
  getForUse(realmId: string, path: string): Promise<string | undefined>;
}

/** The paths of the secret fields of `registry`: the names a {@link RealmSecretStore} keeps values under. */
export function realmSecretPaths(registry: PolicyRegistry = REALM_POLICY_REGISTRY): string[] {
  return registry
    .fields()
    .filter((entry) => entry.field.secret)
    .map((entry) => entry.path);
}
