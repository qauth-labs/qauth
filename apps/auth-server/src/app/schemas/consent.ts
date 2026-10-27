import { z } from 'zod';

import { OAUTH_OPAQUE_PARAM_MAX_LENGTH, OAUTH_SCOPE_PARAM_MAX_LENGTH } from '../constants';
import { clientIdParamSchema, exactUrl } from './common';
import {
  codeChallengeParamSchema,
  dpopJktParamSchema,
  maxAgeParamSchema,
  resourceParamSchema,
} from './oauth';

/**
 * The Allow / Deny form the consent screen posts to `POST /ui/consent` (issue
 * #150): the decision, the "remember this decision" box, the CSRF token bound
 * to the session, and a mirror of `authorizeQuerySchema`'s parameters.
 *
 * Exported here, beside the other request schemas, so the domain graph's
 * extractor (#563) reads it with them.
 */
export const consentFormSchema = z.object({
  decision: z.enum(['allow', 'deny']),
  allow_forever: z.string().optional(),
  csrf_token: z.string().min(1),
  // Mirror of the original authorize params so we don't need to stash them
  // in the session (keeps the session payload small + stateless enough).
  // Same bound as `authorizeQuerySchema.client_id`.
  client_id: clientIdParamSchema,
  // Same exact-string rule as `authorizeQuerySchema.redirect_uri`.
  redirect_uri: exactUrl(),
  state: z.string().max(OAUTH_OPAQUE_PARAM_MAX_LENGTH).optional(),
  // Mirrors `authorizeQuerySchema`'s bound — the two silently drifted once
  // (#316) and this form POST reaches the same pending-authorization stash.
  scope: z.string().max(OAUTH_SCOPE_PARAM_MAX_LENGTH).optional(),
  nonce: z.string().max(OAUTH_OPAQUE_PARAM_MAX_LENGTH).optional(),
  // Same bound as `authorizeQuerySchema.code_challenge`, which is the one
  // `mintAuthorizationCode` holds the code to: a form the screen did not
  // render cannot reach the mint with a challenge it refuses.
  code_challenge: codeChallengeParamSchema,
  code_challenge_method: z.literal('S256'),
  response_type: z.literal('code'),
  // ADR-007 §2 (#185): step-up params carried through so the POST mint path
  // re-evaluates them server-side (the hidden `scope` field is
  // attacker-controlled, so the dangerous-elevation re-auth gate must run HERE
  // too, not only pre-consent). Empty string ⇒ treated as absent.
  prompt: z.enum(['none', 'login', 'consent']).optional(),
  max_age: maxAgeParamSchema,
  // RFC 8707: carried through as hidden form field(s). `resourceParamSchema`
  // populates an array on `body.resource`.
  resource: resourceParamSchema,
  // RFC 9449 §10 (#480): the DPoP key the code is bound to, as
  // `authorizeQuerySchema` takes it. Rendered, and read, only while DPoP is
  // on.
  dpop_jkt: dpopJktParamSchema,
});

/**
 * The consent form as the route handler reads it.
 */
export type ConsentForm = z.infer<typeof consentFormSchema>;
