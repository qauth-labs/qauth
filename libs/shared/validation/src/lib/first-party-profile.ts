/**
 * First-party client profiles (ADR-017 Decision 2, issue #631).
 *
 * First-partyness is operator-set, never self-asserted: a client is first
 * party only when an operator wrote `oauth_clients.first_party_profile` on it,
 * through the `db:seed-oauth-clients` manifest, the system-client provisioner
 * or, later, a `qauth:admin:security` operation (ADR-019 Decision 7). Four
 * database CHECKs tie a profile to a `private_key_jwt` client that no
 * developer owns, that is not an agent and that neither dynamic registration
 * nor a CIMD document created.
 *
 * - `web_redirect`: a web front-end on the redirect flow, such as the
 *   developer portal. It earns only the consent waiver at `/oauth/authorize`
 *   (ADR-017 Decision 9) and is refused at the authorization challenge
 *   endpoint.
 * - `native_backend`: the backend of a native app, which reaches the
 *   authorization challenge endpoint. Only it carries a
 *   `first_party_policy` ({@link firstPartyPolicySchema}).
 *
 * This module is shared by the seed manifest, which validates what an
 * operator writes, and the auth server, which reads a stored row through
 * {@link resolveFirstPartyProfile}.
 */
import { z } from 'zod';

import { isLoopbackHost, redirectTarget } from './redirect-target';

/** The profiles an operator may set. ADR-017 phase F4 adds `native_attested`. */
export const FIRST_PARTY_PROFILES = ['web_redirect', 'native_backend'] as const;
export type FirstPartyProfile = (typeof FIRST_PARTY_PROFILES)[number];

/** The flows a `native_backend` client may run at the authorization challenge endpoint. */
export const FIRST_PARTY_FLOWS = ['login', 'register', 'reset'] as const;
export type FirstPartyFlow = (typeof FIRST_PARTY_FLOWS)[number];

/** The longest written reason an operator may store with a profile. */
export const FIRST_PARTY_REASON_MAX_LENGTH = 1000;

/**
 * A `native_backend` client's policy, as `oauth_clients.first_party_policy`
 * stores it: a strict object, so an unknown member is a policy that does not
 * parse, never one that is ignored.
 *
 * - `flows`: a non-empty set of {@link FIRST_PARTY_FLOWS}, default `login`
 *   only. An app that registers or resets users lists `register` and `reset`.
 * - `email_code_after_password`: ask for an email code after a correct
 *   password (ADR-017 Decision 5), default `false`.
 * - `pkce_required`: PKCE S256 at the authorization challenge endpoint,
 *   default `true`. Only the redirect flow's rule is absolute; an operator may
 *   switch it off here for one client (ADR-017 question 11).
 *
 * Nothing reads `pkce_required` yet: the authorization challenge endpoint
 * (ADR-017 phase F1) will. That consumer must never relax the project's PKCE
 * rule beyond what this member says: the redirect flow always requires S256,
 * whatever the policy holds, and where PKCE applies no method but S256 is
 * ever accepted (no `plain`).
 */
export const firstPartyPolicySchema = z.strictObject({
  flows: z
    .array(z.enum(FIRST_PARTY_FLOWS))
    .min(1)
    .refine((flows) => new Set(flows).size === flows.length, {
      message: 'flows lists a flow twice',
    })
    .default(['login']),
  email_code_after_password: z.boolean().default(false),
  pkce_required: z.boolean().default(true),
});

/** A parsed policy, every member present. */
export type FirstPartyPolicy = z.output<typeof firstPartyPolicySchema>;

/** A policy as an operator may write it: every member optional. */
export type FirstPartyPolicyInput = z.input<typeof firstPartyPolicySchema>;

/** The client fields {@link resolveFirstPartyProfile} reads, as `oauth_clients` holds them. */
export interface FirstPartyClientFields {
  readonly firstPartyProfile: string | null;
  readonly firstPartyPolicy: unknown;
  readonly tokenEndpointAuthMethod: string;
  readonly grantTypes: readonly string[];
  readonly developerId: string | null;
  readonly isAgent: boolean;
  readonly dynamicRegisteredAt: number | null;
  readonly metadata: Readonly<Record<string, unknown>> | null;
}

/** What a first-party client is, once resolved. */
export type ResolvedFirstPartyProfile =
  | { readonly profile: 'web_redirect' }
  | { readonly profile: 'native_backend'; readonly policy: FirstPartyPolicy };

function isFirstPartyProfile(value: unknown): value is FirstPartyProfile {
  return (FIRST_PARTY_PROFILES as readonly unknown[]).includes(value);
}

/**
 * Resolve a stored client's first-party profile, or `null` when the client is
 * not first party. The one reader of the profile: the authorization challenge
 * endpoint's gate and the consent waiver both go through it.
 *
 * Fails closed. Besides an empty or unknown profile, a client is not first
 * party when its row breaks a rule the database CHECKs hold (another auth
 * method, a developer, an agent, a dynamic or CIMD registration), when a
 * `web_redirect` row carries a policy, when a `native_backend` row lacks the
 * `authorization_code` grant, or when its policy does not parse.
 */
export function resolveFirstPartyProfile(
  client: FirstPartyClientFields
): ResolvedFirstPartyProfile | null {
  const profile = client.firstPartyProfile;
  if (profile === null || !isFirstPartyProfile(profile)) return null;

  if (client.tokenEndpointAuthMethod !== 'private_key_jwt') return null;
  if (client.developerId !== null || client.isAgent || client.dynamicRegisteredAt !== null) {
    return null;
  }
  const registrationType = client.metadata?.['registrationType'];
  if (registrationType === 'dynamic' || registrationType === 'cimd') return null;

  if (profile === 'web_redirect') {
    return client.firstPartyPolicy === null || client.firstPartyPolicy === undefined
      ? { profile }
      : null;
  }

  if (!client.grantTypes.includes('authorization_code')) return null;
  const policy = firstPartyPolicySchema.safeParse(client.firstPartyPolicy);
  return policy.success ? { profile, policy: policy.data } : null;
}

/** RFC 8252 §7.3: a loopback redirect names an IP literal, never `localhost` (§8.3). */
function isLoopbackIpLiteral(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, '');
  if (host === '::1') return true;
  return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host) && isLoopbackHost(host);
}

/**
 * Whether a redirect URI can carry a `native_backend` client's browser leg
 * (ADR-017 Decision 2): the system browser returns the app to it after a
 * `redirect_to_web`. One of
 *
 * - an `https` URI, such as an app-claimed link (RFC 8252 §7.2);
 * - a private-use URI scheme in reverse domain-name form (RFC 8252 §7.1),
 *   such as `com.example.notes:/callback`;
 * - an `http` loopback URI with an IP literal (RFC 8252 §7.3), such as
 *   `http://127.0.0.1/callback`.
 *
 * And always one the consent screen can describe ({@link redirectTarget}),
 * with no fragment (RFC 6749 §3.1.2): an authorization request names the
 * callback without one, and the exact match would never find it.
 * Whether an `https` URI is really claimed by the app and never served by the
 * backend cannot be checked here; that stays a requirement of the profile.
 */
export function isNativeBrowserLegRedirectUri(redirectUri: string): boolean {
  if (redirectUri.includes('#')) return false;
  const target = redirectTarget(redirectUri);
  if (target === undefined) return false;
  const url = new URL(redirectUri);
  if (url.protocol === 'https:') return true;
  if (url.protocol === 'http:') return isLoopbackIpLiteral(url.hostname);
  return target.target === 'app' && target.scheme.includes('.');
}
