import type { ConfigKeyInput } from '../types';
import { defineKeys } from '../types';

/**
 * A rate-limit pair: the most requests per window, and the window in seconds.
 * Every rate-limit key is advanced and seeds nothing.
 */
function rateLimit(
  limitName: string,
  windowName: string,
  what: string,
  limit: string,
  window: string
): ConfigKeyInput[] {
  return [
    {
      name: limitName,
      tier: 'advanced',
      role: 'deployment',
      owner: 'rate-limits',
      default: limit,
      since: '0.1.0',
      docs: `The most ${what} allowed per window.`,
    },
    {
      name: windowName,
      tier: 'advanced',
      role: 'deployment',
      owner: 'rate-limits',
      default: window,
      since: '0.1.0',
      docs: `The window, in seconds, of \`${limitName}\`.`,
    },
  ];
}

/** Rate limits: the keys of `rateLimitEnvSchema` and the limits of `authEnvSchema`. */
export const RATE_LIMIT_KEYS = defineKeys([
  {
    name: 'RATE_LIMIT_ENABLED',
    tier: 'advanced',
    role: 'deployment',
    owner: 'rate-limits',
    default: 'true',
    since: '0.1.0',
    docs: 'Apply the rate limits at all; only a development or test stack turns them off.',
  },
  ...rateLimit(
    'RATE_LIMIT_MAX',
    'RATE_LIMIT_WINDOW',
    'requests to a route with no limit of its own',
    '100',
    '3600'
  ),
  ...rateLimit(
    'HEALTH_RATE_LIMIT_MAX',
    'HEALTH_RATE_LIMIT_WINDOW',
    'health endpoint requests',
    '1000',
    '60'
  ),
  ...rateLimit(
    'REGISTRATION_RATE_LIMIT',
    'REGISTRATION_RATE_WINDOW',
    'account registrations',
    '3',
    '3600'
  ),
  ...rateLimit(
    'VERIFICATION_RATE_LIMIT',
    'VERIFICATION_RATE_WINDOW',
    'email verification attempts',
    '10',
    '900'
  ),
  ...rateLimit(
    'RESEND_VERIFICATION_RATE_LIMIT',
    'RESEND_VERIFICATION_RATE_WINDOW',
    'verification mail resends per client address',
    '100',
    '60'
  ),
  ...rateLimit(
    'RESEND_VERIFICATION_EMAIL_LIMIT',
    'RESEND_VERIFICATION_EMAIL_WINDOW',
    'verification mail resends per email address',
    '3',
    '3600'
  ),
  {
    name: 'RESEND_VERIFICATION_MIN_INTERVAL',
    tier: 'advanced',
    role: 'deployment',
    owner: 'rate-limits',
    default: '60',
    since: '0.1.0',
    docs: 'The shortest time, in seconds, between two verification mail resends to one address.',
  },
  ...rateLimit('LOGIN_RATE_LIMIT', 'LOGIN_RATE_WINDOW', 'login attempts', '5', '900'),
  ...rateLimit('REFRESH_RATE_LIMIT', 'REFRESH_RATE_WINDOW', 'refresh token requests', '10', '60'),
  ...rateLimit('LOGOUT_RATE_LIMIT', 'LOGOUT_RATE_WINDOW', 'logout requests', '20', '60'),
  {
    name: 'AUTHORIZE_RATE_LIMIT',
    tier: 'advanced',
    role: 'deployment',
    owner: 'rate-limits',
    default: '60',
    since: '0.1.0',
    docs: 'The most authorization requests allowed per window for a `production` realm, the strict tier.',
  },
  {
    name: 'AUTHORIZE_RATE_LIMIT_LENIENT',
    tier: 'advanced',
    role: 'deployment',
    owner: 'rate-limits',
    default: '600',
    since: '0.1.0',
    docs: 'The most authorization requests allowed per window for a `development` or `staging` realm, the lenient tier.',
  },
  {
    name: 'AUTHORIZE_RATE_WINDOW',
    tier: 'advanced',
    role: 'deployment',
    owner: 'rate-limits',
    default: '60',
    since: '0.1.0',
    docs: 'The window, in seconds, of both authorization request limits.',
  },
  {
    name: 'TOKEN_RATE_LIMIT',
    tier: 'advanced',
    role: 'deployment',
    owner: 'rate-limits',
    default: '30',
    since: '0.1.0',
    docs: 'The most token requests allowed per window for a `production` realm, the strict tier.',
  },
  {
    name: 'TOKEN_RATE_LIMIT_LENIENT',
    tier: 'advanced',
    role: 'deployment',
    owner: 'rate-limits',
    default: '300',
    since: '0.1.0',
    docs: 'The most token requests allowed per window for a `development` or `staging` realm, the lenient tier.',
  },
  {
    name: 'TOKEN_RATE_WINDOW',
    tier: 'advanced',
    role: 'deployment',
    owner: 'rate-limits',
    default: '60',
    since: '0.1.0',
    docs: 'The window, in seconds, of both token request limits.',
  },
  ...rateLimit(
    'INTROSPECT_RATE_LIMIT',
    'INTROSPECT_RATE_WINDOW',
    'introspection requests',
    '30',
    '60'
  ),
  ...rateLimit('USERINFO_RATE_LIMIT', 'USERINFO_RATE_WINDOW', 'userinfo requests', '60', '60'),
  ...rateLimit(
    'REGISTER_CLIENT_RATE_LIMIT',
    'REGISTER_CLIENT_RATE_WINDOW',
    'dynamic client registrations per client address',
    '30',
    '60'
  ),
  ...rateLimit(
    'OID4VP_RESPONSE_RATE_LIMIT',
    'OID4VP_RESPONSE_RATE_WINDOW',
    'wallet responses to `POST /oid4vp/response` per client address',
    '30',
    '60'
  ),
  ...rateLimit(
    'OID4VP_REQUEST_OBJECT_RATE_LIMIT',
    'OID4VP_REQUEST_OBJECT_RATE_WINDOW',
    'request object fetches from `GET /oid4vp/request/:handle` per client address',
    '30',
    '60'
  ),
]);
