import { REALM_POLICY_REGISTRY } from '@qauth-labs/server-realm-policy';
import { findEventNames } from '@qauth-labs/shared-events';
import { describe, expect, it } from 'vitest';

/**
 * Admin events are always on (ADR-020 §3, issues #459 and #827): no realm
 * setting turns them off. Since #516 the realm policies are members of
 * `realms.policies`, whose column type declares none, so the realm tables'
 * test in `infra-db` cannot see them: this twin scans every group and field
 * name of the registry the policy store parses with. A name that holds an
 * event word (`event`, `audit`, `log`, `sink`, …) fails it until it is listed
 * here with the reason it turns nothing off.
 */
const ALLOWED: Readonly<Record<string, string>> = {};

/** Every group and field name of the registry, and every dotted path. */
function policyNames(): string[] {
  return REALM_POLICY_REGISTRY.fields().flatMap(({ path, segments }) => [path, ...segments]);
}

describe('admin events are always on — realm policies', () => {
  it('lists every realm policy name that holds an event word, with its reason', () => {
    expect(findEventNames(policyNames(), ALLOWED)).toEqual([]);
  });

  it('scans every field of the registry', () => {
    expect(policyNames()).toEqual(
      expect.arrayContaining(['tokens.accessTokenLifespanSeconds', 'mail', 'smtp', 'password'])
    );
  });

  it('fails on a policy such as admin.auditEnabled', () => {
    expect(findEventNames([...policyNames(), 'admin.auditEnabled'], ALLOWED)).toEqual([
      'admin.auditEnabled',
    ]);
  });
});
