/** The textual form of a UUID, the type of `realms.id` and `realm_keys.realm_id`. */
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Whether `value` is a realm id: a UUID, in any case. */
export function isRealmId(value: unknown): value is string {
  return typeof value === 'string' && UUID_PATTERN.test(value);
}
