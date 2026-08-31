import { JWTInvalidError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';

/**
 * Who owns a dynamically registered client (issue #374).
 *
 * THE PROBLEM. Both dynamic registration paths created clients with
 * `developerId: null`, and every developer-facing query keys on that column —
 * `GET /api/clients` lists by `listByDeveloper(developerId)`, and per-client
 * access is gated on `client.developerId !== developerId`. A row whose
 * `developer_id` is NULL matches no developer, so a dynamically registered
 * client could not be listed, viewed, edited, deleted, or have its secret
 * regenerated from the developer portal. `README.md` calls CIMD "the primary
 * client-registration path (MCP 2025-11-25)", so the registration route the
 * project positions first produced clients nobody could administer.
 *
 * THE DECISION. Attribute when — and only when — the request carries a
 * developer access token. Anonymous registration stays anonymous.
 *
 * A client that registers itself with no credential genuinely has no developer
 * to attribute to, and inventing one would be worse than leaving it unowned:
 * it would hand an anonymous caller's client to whoever the server guessed.
 * But the converse case is real and was simply unserved — a developer signed
 * into the portal, or running a CLI with their token, who registers a client
 * through RFC 7591 and then cannot see it. That is now attributed.
 *
 * WHY NOT THE OTHER OPTIONS (recorded so they are not silently re-litigated):
 *
 *   - **A CIMD claim flow** — a developer proving control of the metadata
 *     document's origin and adopting the client — is a real feature and the
 *     right long-term answer for CIMD. It is not this: CIMD materialisation
 *     happens while resolving a `client_id` URL during `/oauth/authorize`,
 *     where there is no developer in the request at all, so no amount of
 *     plumbing here reaches it.
 *   - **Realm-scoped operator visibility**, distinct from developer ownership,
 *     is a separate surface with its own authorization model. Worth having;
 *     not a substitute for attribution.
 *
 * SECURITY. This is strictly additive. The token goes through the same
 * verification `requireJwt` uses — this server's issuer pinned (RFC 9700
 * mix-up defence), signature checked, revocation honoured — and a developer can
 * only ever attribute a client to themselves, because the owner is taken from
 * the token's own `sub`. It grants no capability that authenticating to
 * `POST /api/clients` would not already grant.
 */

/**
 * A developer's `users.id`. A `client_credentials` token's `sub` is a client
 * id, not a user, and `oauth_clients.developer_id` is a UUID column with a
 * foreign key — so a non-UUID subject cannot own a client. Same guard, for the
 * same reason, as `POST /api/clients` (`routes/clients/index.ts`).
 */
const uuidSubjectSchema = z.uuid();

/**
 * The developer to attribute a dynamic registration to, or `null`.
 *
 * - **No `Authorization` header** → `null`. Open-mode registration is
 *   unchanged, which is the overwhelmingly common case and the one RFC 7591
 *   describes.
 * - **A header that does not verify** → throws. Deliberately NOT a silent
 *   fall-through to anonymous: a caller who presents a token is asking for
 *   attribution, and quietly registering an unowned client instead would
 *   reproduce the exact failure this issue is about — a client the developer
 *   believes they own and cannot find. Failing loudly is the only outcome that
 *   tells them.
 * - **A verified token whose `sub` is not a user UUID** → also throws, for the
 *   same reason: a `client_credentials` token cannot own a client, and
 *   pretending otherwise would produce a row with a dangling `developer_id`.
 */
export async function resolveRegistrationDeveloperId(
  fastify: FastifyInstance,
  request: FastifyRequest
): Promise<string | null> {
  const header = request.headers.authorization;
  if (!header) return null;

  // Reuses the shared preHandler rather than re-implementing verification, so
  // issuer pinning and revocation cannot drift between the two paths. It
  // throws `JWTInvalidError` on a malformed header, a bad signature, a foreign
  // issuer or a revoked token.
  //
  // Called with the request alone: `requireJwt`'s DECLARED type takes a reply
  // for Fastify's `preHandler` signature, but its implementation
  // (`fastify-plugin-jwt.ts`) takes only the request and never touches a reply
  // — it signals failure by throwing. Narrowing the type here is honest about
  // that; passing a fake reply object would be worse, because it would suggest
  // one is used.
  const verify = fastify.requireJwt as unknown as (req: FastifyRequest) => Promise<void>;
  await verify(request);

  const sub = request.jwtPayload?.sub;
  if (!sub || !uuidSubjectSchema.safeParse(sub).success) {
    throw new JWTInvalidError(
      'A user access token is required to attribute a dynamically registered client'
    );
  }
  return sub;
}
