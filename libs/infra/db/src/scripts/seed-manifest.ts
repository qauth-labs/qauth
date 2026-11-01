/**
 * The manifest `seed-oauth-clients.ts` reads.
 *
 * Kept apart from the script so the validation can be tested without running
 * it, like `client-suspension.ts`.
 */
import {
  FIRST_PARTY_PROFILES,
  FIRST_PARTY_REASON_MAX_LENGTH,
  type FirstPartyPolicy,
  firstPartyPolicySchema,
  InvalidVerifiedDomainError,
  InvalidWebAuthnOriginError,
  isNativeBrowserLegRedirectUri,
  isReservedAudience,
  isReservedQauthScope,
  normaliseVerifiedDomain,
  normaliseWebAuthnOrigin,
  redirectTarget,
} from '@qauth-labs/shared-validation';
import { z } from 'zod';

import {
  agentModeEnum,
  grantTypeEnum,
  responseTypeEnum,
  tokenEndpointAuthMethodEnum,
} from '../lib/schema/enums';
import { systemClientSpecSchema } from '../lib/system-client/provision';
import { publicJwkSchema } from '../lib/system-client/public-jwk';

// Reuse pgEnum values to stay in lock-step with the database schema. If
// someone adds a grant type or auth method to the enum, the manifest
// validator picks it up automatically.
const grantTypeZ = z.enum(grantTypeEnum.enumValues);
const responseTypeZ = z.enum(responseTypeEnum.enumValues);
const tokenEndpointAuthMethodZ = z.enum(tokenEndpointAuthMethodEnum.enumValues);
const agentModeZ = z.enum(agentModeEnum.enumValues);

/**
 * A single JWK inside a manifest-supplied key set: public only, with the
 * members its key type needs (`publicJwkSchema`, shared with the system
 * client's provisioner). The AS only ever needs a client's PUBLIC key to
 * verify a `private_key_jwt` assertion, so a manifest carrying a private
 * component is an operator mistake worth failing loudly on rather than
 * silently persisting into the database.
 */
const clientJwkZ = publicJwkSchema;

/**
 * One operator-set passkey origin (#467), written in the form a browser puts in
 * `clientDataJSON.origin`: an https origin, or an Android app's
 * `android:apk-key-hash:` origin. The refusal names the entry, since it is the
 * operator's own manifest.
 */
const webauthnOriginZ = z.string().transform((value, ctx) => {
  try {
    return normaliseWebAuthnOrigin(value);
  } catch (error) {
    if (!(error instanceof InvalidWebAuthnOriginError)) throw error;
    ctx.addIssue({ code: 'custom', message: `"${value}": ${error.message}` });
    return z.NEVER;
  }
});

/**
 * The domain the operator verified for the client (#593), stored in the form
 * the screens show it: lower case, `xn--` labels for an internationalised name.
 */
const verifiedDomainZ = z.string().transform((value, ctx) => {
  try {
    return normaliseVerifiedDomain(value);
  } catch (error) {
    if (!(error instanceof InvalidVerifiedDomainError)) throw error;
    ctx.addIssue({ code: 'custom', message: `"${value}": ${error.message}` });
    return z.NEVER;
  }
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
    // Each one a URI the consent screen can show where the code goes to
    // (ADR-019 Decision 6, #593), as every registration path requires.
    redirect_uris: z
      .array(
        z.url().refine((uri) => redirectTarget(uri) !== undefined, {
          error: (issue) =>
            `"${String(issue.input)}": the consent screen cannot show where this redirect URI goes: name a DNS host of valid labels, an IPv4 address or a loopback address, or a scheme of at most 64 characters`,
        })
      )
      .optional(),
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
    // ADR-017 Decision 14 (#467): the origins a native app's passkey
    // ceremonies may come from, beside the realm's own. Operator-set only, like
    // `jwks`: no registration path accepts it, so a client cannot widen where
    // its passkeys may be used.
    webauthn_allowed_origins: z.array(webauthnOriginZ).max(20).optional(),
    // RFC 9449 §5.2 (ADR-014 §3, ADR-017 phase F3, #480): the client always
    // uses DPoP at the token endpoint, so a token request without a proof is
    // refused while DPOP_ENABLED is on. Operator-set only, like
    // `max_agent_mode`: no registration path accepts it. Omitted ⇒ false.
    dpop_bound_access_tokens: z.boolean().optional(),
    // ADR-019 Decision 6 (#593): the domain consent, device-code entry, logout
    // and the account console show first for this client, above the name it
    // declares. Admin-set only: setting it is a security operation of the
    // admin API (`clients.update`), and until that ships this manifest is the
    // only path. No registration path accepts it. Omitted ⇒ NULL ⇒ the
    // screens say the app is unverified.
    verified_domain: verifiedDomainZ.optional(),
    // ADR-017 Decision 2 (#631): the client's first-party profile. Set it only
    // for an app the entity that operates this server controls and that users
    // see under that entity's brand; another entity's app, a tenant's
    // included, uses `/oauth/authorize` as a third party. `web_redirect` earns
    // the consent waiver at `/oauth/authorize`; `native_backend` reaches the
    // authorization challenge endpoint. Operator-set only, like
    // `max_agent_mode`: no registration path accepts it, and the database
    // refuses it on a dynamic, CIMD, agent or developer-owned client. Removing
    // it on `--rotate` revokes every refresh token of the client. Omitted ⇒
    // NULL ⇒ not first party.
    first_party_profile: z.enum(FIRST_PARTY_PROFILES).optional(),
    // A `native_backend` client's policy: `flows` (default `["login"]`),
    // `email_code_after_password` (default false), `pkce_required` (default
    // true). Strict: an unknown member is refused. Omitted on a native
    // profile ⇒ the defaults.
    first_party_policy: firstPartyPolicySchema.optional(),
    // The operator's written reason for the profile, stored with the client
    // and recorded in its `client.first_party_changed` event. Required with a
    // profile, refused without one.
    first_party_reason: z.string().trim().min(1).max(FIRST_PARTY_REASON_MAX_LENGTH).optional(),
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
  )
  // ADR-017 Decision 2 (#631). The database CHECKs hold the profile's shape
  // on every path; these say what is wrong in the operator's own terms first,
  // and add the rules only the seed can check.
  .refine(
    (spec) => spec.first_party_profile === undefined || spec.first_party_reason !== undefined,
    {
      message:
        "first_party_profile requires first_party_reason: a written reason why this deployment's operator controls the app and users see it under the operator's brand",
      path: ['first_party_reason'],
    }
  )
  .refine(
    (spec) => spec.first_party_reason === undefined || spec.first_party_profile !== undefined,
    {
      message: 'first_party_reason applies only together with first_party_profile',
      path: ['first_party_reason'],
    }
  )
  .refine(
    (spec) =>
      spec.first_party_policy === undefined || spec.first_party_profile === 'native_backend',
    {
      message: 'first_party_policy applies only to first_party_profile=native_backend',
      path: ['first_party_policy'],
    }
  )
  .refine(
    (spec) =>
      spec.first_party_profile === undefined ||
      spec.token_endpoint_auth_method === 'private_key_jwt',
    {
      message:
        'first_party_profile requires token_endpoint_auth_method=private_key_jwt: no first-party client authenticates with a secret or as a public client',
      path: ['token_endpoint_auth_method'],
    }
  )
  .refine((spec) => spec.first_party_profile === undefined || spec.is_agent !== true, {
    message: 'first_party_profile cannot be set on an agent (is_agent: true)',
    path: ['first_party_profile'],
  })
  .refine(
    (spec) => spec.first_party_profile !== 'native_backend' || Boolean(spec.jwks || spec.jwks_uri),
    {
      message:
        "first_party_profile=native_backend requires the backend's public keys: set jwks or jwks_uri",
      path: ['first_party_profile'],
    }
  )
  .refine(
    (spec) =>
      spec.first_party_profile !== 'native_backend' ||
      spec.grant_types.includes('authorization_code'),
    {
      message: 'first_party_profile=native_backend requires the authorization_code grant',
      path: ['grant_types'],
    }
  )
  .refine(
    (spec) =>
      spec.first_party_profile !== 'native_backend' ||
      (spec.redirect_uris ?? []).some(isNativeBrowserLegRedirectUri),
    {
      message:
        'first_party_profile=native_backend requires at least one redirect URI for the browser leg: an https URI, a private-use scheme in reverse domain-name form (com.example.app:/callback) or an http loopback IP literal (http://127.0.0.1/callback)',
      path: ['redirect_uris'],
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
    // nothing, which is how an operator withdraws one. No scope in QAuth's own
    // `qauth:` namespace (#507, ADR-019 Decision 7): a CIMD client is a
    // self-described public client, and the admin API's scopes are reached
    // only through admin grants (#510), never through this file's grant to a
    // document anyone can host.
    scopes: z.array(
      z
        .string()
        .min(1)
        .refine((scope) => !isReservedQauthScope(scope), {
          error: (issue) =>
            `"${String(issue.input)}" is in the "qauth:" scope namespace, which is reserved for QAuth's own scopes: a CIMD client is never granted one`,
        })
    ),
    // Never a QAuth API audience (#509, ADR-019 Decision 7): a CIMD client is
    // whoever controls its URL, and it never holds a family audience, as its
    // own document cannot claim one either. A pre-registered client of
    // `clients` may.
    audience: z
      .array(
        z
          .string()
          .min(1)
          .refine((value) => !isReservedAudience(value), {
            error: (issue) =>
              `"${String(issue.input)}" is in the "urn:qauth:aud:" audience namespace, which is reserved for QAuth's own API audiences: a CIMD client is never granted one`,
          })
      )
      .nullable()
      .optional(),
  })
  .strict();

export const manifestSchema = z
  .object({
    realm: z.string().min(1),
    clients: z.array(clientSpecSchema).optional(),
    cimd_clients: z.array(cimdClientSpecSchema).optional(),
    // ADR-017 phase F0 (#631): the developer portal's system client, as a
    // `private_key_jwt` client with the `web_redirect` first-party profile
    // and the portal's callback. `client_id` defaults to `system`; set it to
    // the auth server's SYSTEM_CLIENT_ID when that is set. The migration
    // runner provisions the same row from its SYSTEM_CLIENT_* environment.
    system_client: systemClientSpecSchema.optional(),
  })
  .strict()
  .refine(
    (m) =>
      (m.clients?.length ?? 0) + (m.cimd_clients?.length ?? 0) > 0 || m.system_client !== undefined,
    {
      message:
        'the manifest lists no client: add an entry to clients, cimd_clients or system_client',
      path: ['clients'],
    }
  )
  // The system client is provisioned by its own section only, so the rules
  // of its row never meet a `clients` entry's.
  .refine(
    (m) =>
      m.system_client === undefined ||
      ![...(m.clients ?? []), ...(m.cimd_clients ?? [])].some(
        ({ client_id }) => client_id === m.system_client?.client_id
      ),
    {
      message:
        'the system client is listed twice: provision it under system_client only, not under clients or cimd_clients',
      path: ['system_client'],
    }
  )
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

/** A client's first-party columns, as the manifest sets them. */
export interface ClientFirstPartyColumns {
  readonly profile: (typeof FIRST_PARTY_PROFILES)[number] | null;
  readonly policy: FirstPartyPolicy | null;
  readonly reason: string | null;
}

/**
 * The first-party columns a client entry writes (#631). A `native_backend`
 * entry with no policy gets the policy's defaults, so the stored row always
 * holds every member; every other entry writes NULL for all three, which on
 * `--rotate` removes a profile the row had.
 */
export function firstPartyColumnsOf(spec: ClientSpec): ClientFirstPartyColumns {
  const profile = spec.first_party_profile ?? null;
  if (profile === null) return { profile: null, policy: null, reason: null };
  return {
    profile,
    policy:
      profile === 'native_backend'
        ? (spec.first_party_policy ?? firstPartyPolicySchema.parse({}))
        : null,
    reason: spec.first_party_reason ?? null,
  };
}
export type CimdClientSpec = z.infer<typeof cimdClientSpecSchema>;
export type Manifest = z.infer<typeof manifestSchema>;
