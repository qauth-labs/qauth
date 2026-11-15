import { ANY_CLIENT } from '@qauth-labs/shared-validation';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import { rfc3339 } from '../../api-conventions/time';

/**
 * THE RESOURCE SERVER REPRESENTATION OF THE ADMIN API (ADR-019 Decision 7,
 * issue #1087): a protected resource a realm registers (`protected_resources`)
 * as an admin reads it, and the state its operations render and bind an
 * approval to.
 *
 * It shows the resource indicator (RFC 8707), each scope the resource
 * defines with its consent text by locale and whether the realm flags it as
 * sensitive, who may ask for the scopes (`any_client` or the listed
 * `client_id`s), and the row's version, which is its `ETag`.
 *
 * Kept apart from the definitions (`./operations.ts`), which the operation
 * registry imports, and from the routes: it imports no environment.
 */

const isoTime = z.iso.datetime();

/** One scope of a resource server, as the representation shows it. */
export const adminResourceServerScopeSchema = z
  .object({
    scope: z.string().meta({ description: 'The scope value a client asks for.' }),
    text: z.record(z.string(), z.string()).meta({
      description:
        'The consent text the consent step shows for the scope, by BCP 47 locale; en is always among them, and shown when no other locale matches.',
    }),
    sensitive: z.boolean().meta({
      description: 'Whether the realm flags the scope as sensitive: the consent step marks it.',
    }),
  })
  .meta({ id: 'AdminResourceServerScope' });

/** The resource server representation. */
export const adminResourceServerSchema = z
  .object({
    id: z.uuid().meta({ description: 'The id the admin API names the resource server by.' }),
    resource: z.string().meta({
      description:
        'The resource indicator (RFC 8707): an absolute URI, matched exactly against the resource of an authorization request. It never changes: a new indicator is a new resource server.',
    }),
    scopes: z.array(adminResourceServerScopeSchema).meta({
      description:
        'The scopes the resource defines. Each is granted only when the authorization request names this resource, to a client the resource is open to, and with the user’s consent.',
    }),
    clients: z.union([z.literal(ANY_CLIENT), z.array(z.string())]).meta({
      description:
        'Who may ask for the scopes: any_client, every client of the realm (CIMD and dynamically registered ones included), or the client_ids listed.',
    }),
    version: z.int().min(1).meta({
      description: 'Raised by one with every change: the resource server’s ETag.',
    }),
    createdAt: isoTime,
    updatedAt: isoTime,
  })
  .meta({ id: 'AdminResourceServer' });

/** A resource server, as the admin API shows it. */
export type AdminResourceServer = z.infer<typeof adminResourceServerSchema>;

/** One scope of a resource server, as the admin API shows it. */
export type AdminResourceServerScope = z.infer<typeof adminResourceServerScopeSchema>;

/** One `protected_resources` row, as the repository returns it. */
export type ProtectedResourceRecord = NonNullable<
  Awaited<ReturnType<FastifyInstance['repositories']['protectedResources']['findById']>>
>;

/** The representation of a stored protected resource: plain copies, never the row's own objects. */
export function adminResourceServerOf(row: ProtectedResourceRecord): AdminResourceServer {
  return {
    id: row.id,
    resource: row.resource,
    scopes: row.scopes.map((entry) => ({
      scope: entry.scope,
      text: { ...entry.text },
      sensitive: entry.sensitive === true,
    })),
    clients: row.anyClient ? ANY_CLIENT : [...row.clientIds],
    version: row.version,
    createdAt: rfc3339(row.createdAt),
    updatedAt: rfc3339(row.updatedAt),
  };
}

/**
 * The version of a resource server: its row version, raised by one with every
 * write, as the opaque value of its `ETag`. An approval approves a request
 * against that version only.
 */
export function adminResourceServerVersion(server: Pick<AdminResourceServer, 'version'>): string {
  return String(server.version);
}
