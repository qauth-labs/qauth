/**
 * One OpenAPI document per API family (ADR-019 Decision 7, ADR-018 §5, #525).
 *
 * The admin, account and developer APIs each publish a document of their own,
 * served at `<prefix>/openapi.json` on the listener that serves the family:
 * the admin document on the admin listener, the account and developer
 * documents on the public one. Each is cut from the OpenAPI document of its
 * listener, which `@fastify/swagger` builds from the routes the listener
 * registered, so an operation whose switch is off is in none of them
 * (ADR-018 §5), and an operation is described once, by its route.
 *
 * The exporter (`openapi-export.ts`) writes the same documents with the same
 * function, so what a listener serves and what the docs site publishes are the
 * same bytes for the same switches. Pure: no environment, no I/O.
 */

import { withReferencedSchemasOnly } from '../openapi-options';
import { API_FAMILIES, API_FAMILY_PREFIXES, type ApiFamily } from './families';

/** The name of the bearer-token security scheme, in every document of the server. */
export const BEARER_SECURITY_SCHEME = 'bearerAuth';

/** The name of the DPoP security scheme (RFC 9449 §7.1), in every document of the server. */
export const DPOP_SECURITY_SCHEME = 'dpopAuth';

/** One OpenAPI security requirement: scheme name to scopes. */
export type SecurityRequirement = Record<string, string[]>;

/**
 * The security of an account or developer operation: a family token sent as
 * a Bearer token, or as a DPoP-bound one while DPOP_ENABLED is on. The family
 * guard (`helpers/family-token.ts`) takes both. Two requirements, either of
 * which is enough. A new array on every call, as each route owns its schema.
 */
export function familyTokenSecurity(): SecurityRequirement[] {
  return [{ [BEARER_SECURITY_SCHEME]: [] }, { [DPOP_SECURITY_SCHEME]: [] }];
}

/** Where a family's own document is served: `<prefix>/openapi.json`. */
export function familyDocumentPath(family: ApiFamily): string {
  return `${API_FAMILY_PREFIXES[family]}/openapi.json`;
}

/**
 * The version of a family's contract, its document's `info.version`: the
 * major version its path carries, `v1-rc.0` for `/admin/v1-rc.0`. Until QAuth
 * 1.0.0 it is a release candidate (ADR-018 §5), so the document never claims
 * the `v1` promise.
 */
export function familyContractVersion(family: ApiFamily): string {
  const version = API_FAMILY_PREFIXES[family].split('/')[2];
  if (version === undefined || version === '') {
    throw new Error(`The prefix of the ${family} API names no version`);
  }
  return version;
}

/** The parts of an OpenAPI document this module reads or writes. */
export interface OpenApiDocument {
  openapi?: string;
  info?: Record<string, unknown>;
  servers?: unknown[];
  tags?: { name: string; description?: string }[];
  paths?: Record<string, Record<string, unknown>>;
  components?: {
    schemas?: Record<string, unknown>;
    securitySchemes?: Record<string, unknown>;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

const BEARER_SCHEME_TEXT = {
  account:
    "An access token (RFC 9068) whose only audience is `urn:qauth:aud:account:v1-rc.0`, whose subject is an enabled user of the realm, and which carries the account scope of the operation's `x-qauth-class`: `Authorization: Bearer <token>`.",
  developer:
    "An access token (RFC 9068) whose only audience is `urn:qauth:aud:developer:v1-rc.0`, with no `act` claim, whose subject is an enabled user of the realm, and which carries the developer scope of the operation's `x-qauth-class`: `Authorization: Bearer <token>`.",
} as const;

const DPOP_FAMILY_SCHEME_TEXT =
  "The same access token bound to a key (RFC 9449): `Authorization: DPoP <token>`, and a `DPoP` header holding a proof signed with the key the token names in `cnf.jkt`, for the request's method and URL. Accepted while the server's DPOP_ENABLED is on.";

/**
 * The admin API's one security scheme (#520): no admin operation takes a
 * Bearer token.
 */
export const ADMIN_DPOP_SCHEME = Object.freeze({
  type: 'http',
  scheme: 'DPoP',
  description:
    "A DPoP-bound admin access token (RFC 9449 §7.1): `Authorization: DPoP <token>`, and a `DPoP` header holding a proof signed with the key the token names in `cnf.jkt`, for the request's method, ADMIN_API_BASE_URL followed by the request's path, an `iat` within 60 seconds, the token's hash as `ath` and a `jti` never used before. A Bearer token is refused.",
});

/** The `info` title and description of each family's document. */
export const FAMILY_DOCUMENT_INFO: Readonly<
  Record<ApiFamily, { readonly title: string; readonly description: string }>
> = Object.freeze({
  admin: {
    title: 'QAuth Admin API',
    description:
      "The admin API of QAuth (ADR-019 Decision 7), served on the internal admin listener only. Every operation needs a DPoP-bound admin token, sent as `Authorization: DPoP <token>` with a proof made with its key for this listener's base URL and the request's path, whose account holds a grant on the realm in the path; a security operation also needs an approval bound to it.",
  },
  account: {
    title: 'QAuth Account API',
    description:
      "The account API of QAuth (ADR-019 Decision 7), `/account/v1-rc.0`, as this server serves it: the operations with which a signed-in person's backend, such as the account console's, manages that person's own account. Every operation needs an access token whose only audience is `urn:qauth:aud:account:v1-rc.0`, sent as a Bearer token or, while DPOP_ENABLED is on, a DPoP-bound one, carrying the account scope of the operation's `x-qauth-class`: `qauth:account:read` or `qauth:account:write`. The whole contract, with the operations still to come, is the account API contract document the docs site publishes at `/account/v1-rc.0/openapi.json`.",
  },
  developer: {
    title: 'QAuth Developer API',
    description:
      "The developer API of QAuth (ADR-019 Decision 7), `/developer/v1-rc.0`: a developer manages their OAuth clients, the clients' API keys and, until the account console takes them over, their own consents. Every operation needs an access token whose only audience is `urn:qauth:aud:developer:v1-rc.0`, sent as a Bearer token or, while DPOP_ENABLED is on, a DPoP-bound one, carrying the developer scope of the operation's `x-qauth-class`: `qauth:developer:read` or `qauth:developer:write`.",
  },
});

/** The server entry of each family's document. */
const FAMILY_SERVERS: Readonly<Record<ApiFamily, { url: string; description: string }>> =
  Object.freeze({
    admin: {
      url: '/',
      description:
        "The admin listener, at ADMIN_API_BASE_URL. A proof's `htu` is that URL followed by the request's path.",
    },
    account: {
      url: '/',
      description:
        "The auth server's origin for the realm, the issuer's. A caller's backend calls it server to server.",
    },
    developer: {
      url: '/',
      description:
        "The auth server's origin for the realm, the issuer's. A caller's backend calls it server to server.",
    },
  });

/** The security schemes each family's document defines: the ones its operations take. */
function familySecuritySchemes(family: ApiFamily): Record<string, unknown> {
  if (family === 'admin') return { [DPOP_SECURITY_SCHEME]: { ...ADMIN_DPOP_SCHEME } };
  return {
    [BEARER_SECURITY_SCHEME]: {
      type: 'http',
      scheme: 'bearer',
      bearerFormat: 'JWT',
      description: BEARER_SCHEME_TEXT[family],
    },
    [DPOP_SECURITY_SCHEME]: {
      type: 'http',
      scheme: 'DPoP',
      description: DPOP_FAMILY_SCHEME_TEXT,
    },
  };
}

/** The HTTP methods an OpenAPI path item holds operations under. */
const OPERATION_METHODS = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace'];

/** Whether `path` is an operation path of `family`: under its prefix, not its own document. */
function isFamilyOperationPath(path: string, family: ApiFamily): boolean {
  return path.startsWith(`${API_FAMILY_PREFIXES[family]}/`) && path !== familyDocumentPath(family);
}

/**
 * The OpenAPI document of `family`, cut from `source`, the document of the
 * listener that serves it:
 *
 * - the paths under the family's prefix, in `source`'s order, and no other;
 * - the family's own `info`, with the contract version as `info.version`
 *   ({@link familyContractVersion}), its server entry, and the security
 *   schemes its operations take (Bearer and DPoP; DPoP alone on the admin
 *   API);
 * - the tags its operations use, and the component schemas they reference,
 *   directly or through another schema.
 *
 * Deterministic: the same source gives the same document, key for key. Never
 * changes `source`.
 */
export function familyDocument(source: OpenApiDocument, family: ApiFamily): OpenApiDocument {
  const paths: Record<string, Record<string, unknown>> = {};
  const usedTags = new Set<string>();
  for (const [path, item] of Object.entries(source.paths ?? {})) {
    if (!isFamilyOperationPath(path, family)) continue;
    const copy = structuredClone(item);
    paths[path] = copy;
    for (const method of OPERATION_METHODS) {
      const tags = (copy[method] as { tags?: unknown } | undefined)?.tags;
      if (Array.isArray(tags)) for (const tag of tags) usedTags.add(String(tag));
    }
  }
  const tags = (source.tags ?? [])
    .filter((tag) => usedTags.has(tag.name))
    .map((tag) => structuredClone(tag));

  const document: OpenApiDocument = {
    openapi: source.openapi ?? '3.1.0',
    info: { ...FAMILY_DOCUMENT_INFO[family], version: familyContractVersion(family) },
    servers: [{ ...FAMILY_SERVERS[family] }],
    ...(tags.length > 0 ? { tags } : {}),
    paths,
    components: {
      securitySchemes: familySecuritySchemes(family),
      schemas: structuredClone(source.components?.schemas ?? {}),
    },
  };
  return withReferencedSchemasOnly(document);
}

/** The bytes of a published document: two-space JSON and a final newline, as every export. */
export function serializeDocument(document: unknown): string {
  return `${JSON.stringify(document, null, 2)}\n`;
}

/** Every family, in the order the exporter writes them. */
export const DOCUMENT_FAMILIES: readonly ApiFamily[] = API_FAMILIES;
