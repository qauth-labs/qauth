import { z } from 'zod';

import { defineEventType } from '../definition';
import { extensibleEnum } from '../envelope';
import {
  CAEP_SESSION_REVOKED,
  CAEP_TOKEN_CLAIMS_CHANGE,
  QAUTH_TOKEN_REVOKED,
} from '../ssf-mapping';
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
  security: true,
  ssf: 'none',
  ssfNote:
    'CAEP 1.0 §3.4 `assurance-level-change` signals that the authentication method changed, and needs the level before and after in a namespace. QAuth’s step-up asks for a fresh sign-in with the same method and records no assurance level, so that event would say nothing true. It maps once step-up can raise the level, with passkeys or TOTP (ADR-018 §3).',
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
  security: true,
  ssf: {
    event: CAEP_TOKEN_CLAIMS_CHANGE,
    clientOnly: true,
    members: { claims: { value: { scope: '' } } },
  },
  ssfNote:
    'A withdrawn consent covered every scope the client held for the user, so the `scope` of its tokens for that user is now empty, and QAuth revoked the refresh tokens the consent covered.',
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
    refreshFamilyId: recordId(
      'The refresh family a replayed grant (reason `code_replay` or `refresh_replay`) had issued, which the refusal revoked. Absent when the grant issued none.'
    ).optional(),
    revokedRefreshCount: count(
      'How many refresh tokens of that family the refusal revoked; 0 when they were revoked already. Present for the reasons `code_replay` and `refresh_replay`.'
    ).optional(),
  }),
});

/** The replays that revoke a refresh family (RFC 9700 §2.2.2, OAuth 2.1 §4.1.3). */
export const REPLAY_REASONS = ['code_replay', 'refresh_replay'] as const;

export const tokenFamilyRevoked = defineEventType({
  name: 'token.family_revoked',
  version: 1,
  rc: 0,
  description:
    'A replayed grant made QAuth revoke the refresh family it had issued: an authorization code redeemed a second time, or a refresh token presented after it was rotated or revoked. Emitted only when the replay revoked refresh tokens, beside the `token.request_failed` that refused it.',
  category: 'user',
  severity: 'critical',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    reason: extensibleEnum(REPLAY_REASONS).describe(
      '`code_replay`: an authorization code redeemed a second time. `refresh_replay`: a refresh token presented after it was rotated or revoked. The set may grow in a minor release.'
    ),
    refreshFamilyId: recordId('The refresh family that was revoked.'),
    revokedRefreshCount: count('How many refresh tokens of the family were revoked, at least 1.'),
  }),
  security: true,
  ssf: {
    event: CAEP_SESSION_REVOKED,
    clientOnly: true,
    initiatingEntity: 'policy',
    members: {
      reason_admin: {
        data: 'reason',
        map: {
          code_replay: {
            en: 'An authorization code was redeemed a second time; the refresh tokens it had issued were revoked.',
          },
          refresh_replay: {
            en: 'A refresh token was presented after it was rotated or revoked; its family was revoked.',
          },
        },
      },
    },
  },
  ssfNote:
    'A refresh family is the client’s standing session for the user, so its revocation is `session-revoked`. The replay policy revoked it, so `initiating_entity` is `policy`.',
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
  security: true,
  ssf: {
    event: QAUTH_TOKEN_REVOKED,
    clientOnly: true,
    members: { token_type_hint: { data: 'typeHint' } },
  },
  ssfNote:
    'Sent only when the revoked token was a user’s: the event’s subject. A revocation that matched no token of the client records the event without one, and no stream receives it.',
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
  tokenFamilyRevoked,
  tokenRevoked,
  tokenRevocationFailed,
  tokenIntrospected,
  tokenIntrospectionFailed,
  userinfoServed,
  userinfoRequestFailed,
] as const;
