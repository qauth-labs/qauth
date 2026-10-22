import { InvalidRealmHostError, normaliseRealmHost } from '@qauth-labs/shared-validation';
import { z } from 'zod';

/**
 * Parse `DEFAULT_REALM_ENDPOINT_HOSTS` (#484): host names, separated by commas,
 * that the auth server adds to the default realm as endpoint hosts at boot
 * (ADR-019 Decision 1). Each name is normalised as an endpoint host, so it
 * comes out lower case, in ASCII and without a port, and an IP literal is
 * kept. Blank entries and repeats are dropped.
 *
 * Refuses the boot, naming the variable and the entry, when an entry cannot be
 * a realm host: a wildcard, a URL, white space inside a name, an empty label.
 */
export function parseRealmEndpointHosts(raw: string, ctx: z.RefinementCtx): readonly string[] {
  const hosts = new Set<string>();
  let valid = true;
  for (const entry of raw.split(',').map((value) => value.trim())) {
    if (entry.length === 0) continue;
    try {
      hosts.add(normaliseRealmHost(entry, 'endpoint'));
    } catch (error) {
      if (!(error instanceof InvalidRealmHostError)) throw error;
      ctx.addIssue({
        code: 'custom',
        message: `DEFAULT_REALM_ENDPOINT_HOSTS entry "${entry}" is not a host name: ${error.message}. Write the bare name a server-side caller uses, such as auth-server, with no scheme or path.`,
      });
      valid = false;
    }
  }
  return valid ? Object.freeze([...hosts]) : z.NEVER;
}
