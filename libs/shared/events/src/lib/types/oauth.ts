import { z } from 'zod';

import { defineEventType } from '../definition';
import { count, FIRST_RELEASE, oauthError, reason, recordId, scopeList, scopeMode } from './fields';

/**
 * The OAuth and OpenID Connect endpoints: authorization, consent, step-up,
 * the token endpoint, revocation, introspection and userinfo. The client is
 * in the envelope's `client`; the user, when there is one, is the subject.
 */

const grantType = () =>
  z
    .string()
    .min(1)
    .max(255)
    .describe('The `grant_type` of the token request, such as `authorization_code`.');

const failure = () => ({
  error: oauthError(),
  reason: reason().optional(),
});

export const authorizationCompleted = defineEventType({
  name: 'authorization.completed',
  version: 1,
  rc: 0,
  description:
    'The authorization endpoint sent the client back with an authorization response that grants access.',
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({}),
});

export const authorizationFailed = defineEventType({
  name: 'authorization.failed',
  version: 1,
  rc: 0,
  description:
    'The authorization endpoint refused a request: an unknown client, a redirect URI that is not registered, a scope the client may not have, or a denial.',
  category: 'user',
  severity: 'warning',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject(failure()),
});

export const stepUpRequired = defineEventType({
  name: 'step_up.required',
  version: 1,
  rc: 0,
  description:
    'A request needs a fresh sign-in or new consent before it can go on, for example for a dangerous scope (ADR-007 §2).',
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    reason: reason(),
    error: oauthError().optional(),
    elevatedScopes: scopeList(
      'The scopes the request adds to what the user already granted.'
    ).optional(),
    dangerousScopes: scopeList('The requested scopes classed as dangerous.').optional(),
    prompt: z
      .string()
      .min(1)
      .max(64)
      .optional()
      .describe('The OpenID Connect `prompt` value of the request.'),
    maxAge: z.int().min(0).optional().describe('The `max_age` of the request, in seconds.'),
  }),
});

export const stepUpElevated = defineEventType({
  name: 'step_up.elevated',
  version: 1,
  rc: 0,
  description: 'After a fresh sign-in, a user granted a client dangerous scopes (ADR-007 §2).',
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    scopes: scopeList('Every scope granted.'),
    dangerousScopes: scopeList('The granted scopes classed as dangerous.'),
    scopeMode: scopeMode().optional(),
    authenticatedAt: z.iso
      .datetime()
      .optional()
      .describe('When the fresh sign-in happened, as an RFC 3339 time in UTC.'),
  }),
});

export const consentGranted = defineEventType({
  name: 'consent.granted',
  version: 1,
  rc: 0,
  description: 'A user granted a client the scopes it asked for.',
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    scopes: scopeList('The scopes granted.'),
    remembered: z
      .boolean()
      .describe('Whether the user chose to remember the decision for later requests.'),
    dangerousScopes: scopeList('The granted scopes classed as dangerous.').optional(),
  }),
});

export const consentDenied = defineEventType({
  name: 'consent.denied',
  version: 1,
  rc: 0,
  description:
    'Consent was not given: the user declined, or the request did not match what the consent screen showed.',
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    error: oauthError().optional(),
    reason: reason().optional(),
  }),
});

export const consentRevoked = defineEventType({
  name: 'consent.revoked',
  version: 1,
  rc: 0,
  description:
    "A user withdrew a client's consent. QAuth revoked the refresh tokens the consent covered.",
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    consentId: recordId('The id of the consent that was withdrawn.'),
    revokedRefreshCount: count('How many refresh tokens were revoked with it.').optional(),
  }),
});

export const tokenIssued = defineEventType({
  name: 'token.issued',
  version: 1,
  rc: 0,
  description:
    'The token endpoint issued tokens: for an authorization code, a refresh, client credentials, a token exchange or a JWT bearer assertion.',
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    grantType: grantType(),
    scopes: scopeList('The scopes of the issued access token.').optional(),
    audience: z
      .array(z.string().min(1).max(2048))
      .max(64)
      .optional()
      .describe('The audience of the issued token.'),
    resources: z
      .array(z.string().min(1).max(2048))
      .max(64)
      .optional()
      .describe('The RFC 8707 resource indicators the token is bound to.'),
    expiresIn: z
      .int()
      .min(0)
      .optional()
      .describe('The lifetime of the issued access token, in seconds.'),
    issuedTokenType: z
      .string()
      .min(1)
      .max(255)
      .optional()
      .describe('The RFC 8693 `issued_token_type` of a token exchange.'),
    refreshFamilyId: recordId(
      'The refresh family the issued refresh token belongs to. Every rotation keeps it.'
    ).optional(),
    delegationDepth: z
      .int()
      .min(0)
      .max(16)
      .optional()
      .describe('How many actors the RFC 8693 `act` chain of the issued token holds.'),
    idJagId: z
      .string()
      .min(1)
      .max(255)
      .optional()
      .describe(
        'The `jti` of the identity assertion authorization grant minted or consumed (ADR-011). Never the grant itself.'
      ),
    idJagIssuer: z
      .string()
      .min(1)
      .max(2048)
      .optional()
      .describe('The issuer of a consumed identity assertion authorization grant (ADR-011).'),
    scopeMode: scopeMode().optional(),
  }),
});

export const tokenRequestFailed = defineEventType({
  name: 'token.request_failed',
  version: 1,
  rc: 0,
  description:
    'The token endpoint refused a request: failed client authentication, an invalid or replayed grant, a scope or resource outside what was granted.',
  category: 'user',
  severity: 'warning',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    grantType: grantType().optional(),
    ...failure(),
  }),
});

export const tokenRevoked = defineEventType({
  name: 'token.revoked',
  version: 1,
  rc: 0,
  description: 'A client revoked a token at the RFC 7009 revocation endpoint.',
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    typeHint: z
      .string()
      .min(1)
      .max(64)
      .optional()
      .describe('The `token_type_hint` the client sent, such as `refresh_token`.'),
  }),
});

export const tokenRevocationFailed = defineEventType({
  name: 'token.revocation_failed',
  version: 1,
  rc: 0,
  description:
    'The revocation endpoint refused a request, for example on failed client authentication.',
  category: 'user',
  severity: 'warning',
  since: FIRST_RELEASE,
  data: z.strictObject(failure()),
});

export const tokenIntrospected = defineEventType({
  name: 'token.introspected',
  version: 1,
  rc: 0,
  description: 'A resource server introspected an active token (RFC 7662).',
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    tokenClientId: z
      .string()
      .min(1)
      .max(255)
      .optional()
      .describe('The `client_id` the introspected token was issued to.'),
  }),
});

export const tokenIntrospectionFailed = defineEventType({
  name: 'token.introspection_failed',
  version: 1,
  rc: 0,
  description:
    'An introspection request failed: client authentication, or a token that is invalid, expired, revoked or not one the caller may inspect.',
  category: 'user',
  severity: 'warning',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject(failure()),
});

export const userinfoServed = defineEventType({
  name: 'userinfo.served',
  version: 1,
  rc: 0,
  description: 'The userinfo endpoint returned claims for an access token.',
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({}),
});

export const userinfoRequestFailed = defineEventType({
  name: 'userinfo.request_failed',
  version: 1,
  rc: 0,
  description: 'The userinfo endpoint refused a request.',
  category: 'user',
  severity: 'warning',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject(failure()),
});

export const OAUTH_EVENT_TYPES = [
  authorizationCompleted,
  authorizationFailed,
  stepUpRequired,
  stepUpElevated,
  consentGranted,
  consentDenied,
  consentRevoked,
  tokenIssued,
  tokenRequestFailed,
  tokenRevoked,
  tokenRevocationFailed,
  tokenIntrospected,
  tokenIntrospectionFailed,
  userinfoServed,
  userinfoRequestFailed,
] as const;
