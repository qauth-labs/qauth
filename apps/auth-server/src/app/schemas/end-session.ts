import { z } from 'zod';

import { OAUTH_OPAQUE_PARAM_MAX_LENGTH } from '../constants';
import { clientIdParamSchema, exactUrl } from './common';

/**
 * The longest `id_token_hint` the end-session endpoint reads, in characters.
 * QAuth's ID tokens are EdDSA or RS256 compact JWTs of about one kilobyte; the
 * bound leaves room for a large claims set and keeps the parse of an
 * unauthenticated request cheap.
 */
export const ID_TOKEN_HINT_MAX_LENGTH = 8192;

/** The longest `ui_locales` or `logout_hint` accepted: neither is read today. */
const UNREAD_HINT_MAX_LENGTH = 256;

/**
 * The parameters of the end-session endpoint (OpenID Connect RP-Initiated
 * Logout 1.0 §2, #675), in the query of a GET or the form body of a POST. Each
 * is optional and a single bounded string: a parameter repeated, or longer than
 * its bound, fails the schema with `validation_error`. Unknown parameters are
 * dropped, as at the authorization endpoint.
 */
export const endSessionParamsSchema = z.object({
  id_token_hint: z.string().min(1).max(ID_TOKEN_HINT_MAX_LENGTH).optional().meta({
    description:
      'RP-Initiated Logout 1.0 §2: an ID token this realm issued to the client, expired or not. When it names the browser session (its account by sub, the session by sid), the session ends without a confirmation.',
  }),
  client_id: clientIdParamSchema.optional().meta({
    description:
      'RP-Initiated Logout 1.0 §2: the client asking. With an id_token_hint it must be the hint’s audience.',
  }),
  // exactUrl(), not z.url(): matched as an exact string against the client's
  // registered post_logout_redirect_uris (§3.1).
  post_logout_redirect_uri: exactUrl().optional().meta({
    description:
      'RP-Initiated Logout 1.0 §2: where the browser goes after the logout. Must be one of the client’s registered post_logout_redirect_uris, matched exactly; otherwise QAuth shows an information page and never redirects.',
  }),
  state: z.string().max(OAUTH_OPAQUE_PARAM_MAX_LENGTH).optional().meta({
    description:
      'RP-Initiated Logout 1.0 §2: an opaque value added to the post_logout_redirect_uri when the browser goes back.',
  }),
  ui_locales: z
    .string()
    .max(UNREAD_HINT_MAX_LENGTH)
    .optional()
    .meta({ description: 'RP-Initiated Logout 1.0 §2. Accepted and not read.' }),
  logout_hint: z
    .string()
    .max(UNREAD_HINT_MAX_LENGTH)
    .optional()
    .meta({ description: 'RP-Initiated Logout 1.0 §2. Accepted and not read.' }),
});

export type EndSessionParams = z.infer<typeof endSessionParamsSchema>;

/**
 * The checked logout request a `logout_confirm` interaction holds (#675): the
 * client the request named, once it resolved in the realm, the registered
 * return URI it was checked against, and `state`. Never the hint.
 */
export const logoutRequestSchema = z.strictObject({
  client_id: clientIdParamSchema.optional(),
  post_logout_redirect_uri: exactUrl().optional(),
  state: z.string().max(OAUTH_OPAQUE_PARAM_MAX_LENGTH).optional(),
});

export type LogoutRequest = z.infer<typeof logoutRequestSchema>;
