/**
 * The manifest `seed-oauth-clients.ts` reads.
 *
 * Kept apart from the script so the validation can be tested without running
 * it, like `client-suspension.ts`.
 */
import { z } from 'zod';

import {
  agentModeEnum,
  grantTypeEnum,
  responseTypeEnum,
  tokenEndpointAuthMethodEnum,
} from '../lib/schema/enums';

// Reuse pgEnum values to stay in lock-step with the database schema. If
// someone adds a grant type or auth method to the enum, the manifest
// validator picks it up automatically.
const grantTypeZ = z.enum(grantTypeEnum.enumValues);
const responseTypeZ = z.enum(responseTypeEnum.enumValues);
const tokenEndpointAuthMethodZ = z.enum(tokenEndpointAuthMethodEnum.enumValues);
const agentModeZ = z.enum(agentModeEnum.enumValues);

/**
 * A single JWK inside a manifest-supplied key set. Deliberately loose about
 * which members are present (the verifier decides that) but STRICT about one
 * thing: no private-key material. `d` is the private exponent/scalar for RSA,
 * EC and OKP alike; `k` is a symmetric key. The AS only ever needs a client's
 * PUBLIC key to verify a `private_key_jwt` assertion, so a manifest carrying a
 * private component is an operator mistake worth failing loudly on rather than
 * silently persisting into the database.
 */
const clientJwkZ = z
  .object({ kty: z.string().min(1) })
  .catchall(z.unknown())
  .refine((jwk) => !('d' in jwk) && !('k' in jwk), {
    message: 'jwks must contain PUBLIC keys only (a "d" or "k" member was present)',
  });

export const clientSpecSchema = z
  .object({
    client_id: z.string().min(1).max(255),
    name: z.string().min(1).max(255),
    description: z.string().max(2000).optional(),
    grant_types: z.array(grantTypeZ).min(1),
    response_types: z.array(responseTypeZ).optional(),
    scopes: z.array(z.string().min(1)).optional(),
    audience: z.array(z.string().min(1)).nullable().optional(),
    redirect_uris: z.array(z.url()).optional(),
    require_pkce: z.boolean().optional(),
    token_endpoint_auth_method: tokenEndpointAuthMethodZ.optional(),
    // ADR-007 §2: classify a seeded client as an autonomous AI agent.
    // Defaults to false (standard client) when omitted, mirroring the schema
    // column default so existing manifests are unaffected.
    is_agent: z.boolean().optional(),
    // ADR-007 §2 (#184): operator-set MAXIMUM agent scope mode. This is the
    // intended provisioning path for the cap — it is deliberately NOT
    // accepted from a client's own DCR/CIMD registration (an escalation
    // control must be server-set). Omitted ⇒ NULL ⇒ no agent mode permitted
    // (deny-by-default). Only meaningful together with `is_agent: true`.
    max_agent_mode: agentModeZ.optional(),
    // ADR-011 (#434): the foreign authorization servers and MCP servers this
    // client may name when it mints an ID-JAG, and the resources it may redeem
    // one for. Separate from `audience`, which bounds the QAuth tokens
    // `client_credentials` issues. Like `max_agent_mode`, this manifest is the
    // only path that sets it. Omitted ⇒ `[]` ⇒ no ID-JAG target (deny).
    id_jag_targets: z.array(z.string().min(1)).optional(),
    // RFC 7591 §2 client JWKS, consumed by `private_key_jwt` client
    // authentication (#384). This is the ONLY provisioning path for it:
    // `POST /oauth/register` (DCR) does not accept `jwks` / `jwks_uri` or the
    // `private_key_jwt` auth method, so a client cannot self-register the keys
    // that authenticate it — same operator-set posture as `max_agent_mode`.
    jwks: z.object({ keys: z.array(clientJwkZ).min(1).max(20) }).optional(),
    jwks_uri: z.url().max(2048).optional(),
  })
  .strict()
  // RFC 7591 §2: "The `jwks_uri` and `jwks` parameters MUST NOT both be
  // present in the same request or response." Enforced HERE, at the validation
  // layer, rather than as a DB CHECK so the operator gets a message naming the
  // conflict instead of a constraint violation.
  .refine((spec) => !(spec.jwks && spec.jwks_uri), {
    message: 'jwks and jwks_uri are mutually exclusive (RFC 7591 §2) — set at most one',
    path: ['jwks'],
  })
  // Fail closed on a half-provisioned private_key_jwt client: without a key
  // set there is nothing to verify an assertion against, so the client could
  // never authenticate. Surfacing that at seed time beats a runtime
  // `invalid_client` nobody can explain.
  .refine(
    (spec) =>
      spec.token_endpoint_auth_method !== 'private_key_jwt' || Boolean(spec.jwks || spec.jwks_uri),
    {
      message: 'token_endpoint_auth_method=private_key_jwt requires either jwks or jwks_uri',
      path: ['token_endpoint_auth_method'],
    }
  );

/** Printable ASCII without the space: every character RFC 3986 allows in a URI. */
const URI_CHARACTERS = /^[\x21-\x7E]*$/;

/**
 * Whether `value` has the shape the auth server's `isCimdClientId`
 * (`apps/auth-server/src/app/helpers/cimd.ts`) resolves as a CIMD `client_id`:
 * an ASCII `https` URL with a path beyond `/` and no fragment. A `client_id`
 * of any other shape would never be resolved from a document, so the seed
 * refuses it rather than write a row the auth server cannot use.
 */
export function isCimdClientIdShape(value: string): boolean {
  if (!URI_CHARACTERS.test(value)) return false;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  if (parsed.protocol !== 'https:') return false;
  if (parsed.pathname === '' || parsed.pathname === '/') return false;
  return !parsed.hash;
}

/**
 * An operator's grant to a CIMD client (#770): the scopes it may receive and
 * the audience its tokens default to. Nothing else, because the client's
 * metadata document owns every other field and re-resolution rewrites them
 * (ADR-012). No secret either: a CIMD client has none.
 */
export const cimdClientSpecSchema = z
  .object({
    client_id: z.string().min(1).max(255).refine(isCimdClientIdShape, {
      message: 'client_id must be a CIMD client_id: an https URL with a path and no fragment',
    }),
    // Required, so an entry always states the grant. An empty list grants
    // nothing, which is how an operator withdraws one.
    scopes: z.array(z.string().min(1)),
    audience: z.array(z.string().min(1)).nullable().optional(),
  })
  .strict();

export const manifestSchema = z
  .object({
    realm: z.string().min(1),
    clients: z.array(clientSpecSchema).optional(),
    cimd_clients: z.array(cimdClientSpecSchema).optional(),
  })
  .strict()
  .refine((m) => (m.clients?.length ?? 0) + (m.cimd_clients?.length ?? 0) > 0, {
    message: 'the manifest lists no client: add an entry to clients or cimd_clients',
    path: ['clients'],
  })
  // One row per client_id: a CIMD entry may not name a client the manifest
  // also provisions, or another CIMD entry.
  .refine(
    (m) => {
      const seen = new Set((m.clients ?? []).map((c) => c.client_id));
      for (const { client_id } of m.cimd_clients ?? []) {
        if (seen.has(client_id)) return false;
        seen.add(client_id);
      }
      return true;
    },
    { message: 'a cimd_clients client_id is listed twice in the manifest', path: ['cimd_clients'] }
  );

export type ClientSpec = z.infer<typeof clientSpecSchema>;
export type CimdClientSpec = z.infer<typeof cimdClientSpecSchema>;
export type Manifest = z.infer<typeof manifestSchema>;
