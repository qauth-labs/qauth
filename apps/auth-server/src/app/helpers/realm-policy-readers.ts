/**
 * The realm policies the auth server reads from the realm row (ADR-019
 * Decision 10, #516), by their path in the realm policy schema.
 *
 * Since #516 every realm stores its policies, and the environment only
 * seeds a new realm. The flows move to the stored values one area at a time:
 * the token lifetimes (#527), the verified-account, password and brute-force
 * policy (#528), mail (#529) and CIMD (#534). Until an area has moved, the
 * server still reads its keys from the environment for every realm, so the
 * default realm's boot step says a set key is ignored only for a path listed
 * here; for any other it says the server still applies the key. The issue
 * that moves an area adds its paths.
 */
export const POLICIES_READ_FROM_REALM_ROW: ReadonlySet<string> = new Set([
  // `/oauth/register` and the clients API (`routes/clients/index.ts`) cap a
  // client's scopes with the realm's list; the environment's list fills an
  // empty one only while the realm has no policies.
  'registration.dynamicRegistrationAllowedScopes',
  // `resolveEnvironmentPolicy` (ADR-008): the realm's environment ceiling.
  'posture.maxEnvironmentLaxity',
]);
