import { describe, expect, it } from 'vitest';

import { authEnvSchema } from './auth';

/**
 * DEFAULT_REALM_ENDPOINT_HOSTS (#484) names the hosts the boot step adds to the
 * default realm as endpoint hosts, such as `auth-server` from the developer
 * portal's `AUTH_SERVER_URL`. Each comes out in the stored form, and a value
 * that cannot be a host refuses the boot.
 */
function endpointHosts(raw: string | undefined): readonly string[] {
  return authEnvSchema.parse(raw === undefined ? {} : { DEFAULT_REALM_ENDPOINT_HOSTS: raw })
    .DEFAULT_REALM_ENDPOINT_HOSTS;
}

/** The boot errors for `raw`, as the operator reads them. */
function bootErrors(raw: string): string[] {
  const result = authEnvSchema.safeParse({ DEFAULT_REALM_ENDPOINT_HOSTS: raw });
  if (result.success) return [];
  return result.error.issues.map((issue) => `${issue.path.join('.')}: ${issue.message}`);
}

describe('authEnvSchema DEFAULT_REALM_ENDPOINT_HOSTS', () => {
  it('is empty when unset or blank', () => {
    expect(endpointHosts(undefined)).toEqual([]);
    expect(endpointHosts('')).toEqual([]);
    expect(endpointHosts(' , ,')).toEqual([]);
  });

  it('splits on commas, trims, and drops repeats in any spelling', () => {
    expect(endpointHosts('auth-server')).toEqual(['auth-server']);
    expect(endpointHosts(' auth-server , Auth-Server:3000, auth.internal. ')).toEqual([
      'auth-server',
      'auth.internal',
    ]);
  });

  it('keeps an IP literal, which an endpoint host may be', () => {
    expect(endpointHosts('10.0.0.5:3000, [::1]')).toEqual(['10.0.0.5', '[::1]']);
  });

  it('writes an internationalised name in its ASCII form', () => {
    expect(endpointHosts('bücher.internal')).toEqual(['xn--bcher-kva.internal']);
  });

  it.each(['http://auth-server:3000', '*.internal', 'auth server', 'auth..internal', 'a/b'])(
    'refuses %s, naming the variable and the entry',
    (raw) => {
      expect(bootErrors(raw)).toEqual([
        expect.stringMatching(
          /^DEFAULT_REALM_ENDPOINT_HOSTS: DEFAULT_REALM_ENDPOINT_HOSTS entry ".+" is not a host name: /
        ),
      ]);
    }
  );

  it('reports every bad entry, not only the first', () => {
    expect(bootErrors('auth-server, *.a, b/c')).toHaveLength(2);
  });
});
