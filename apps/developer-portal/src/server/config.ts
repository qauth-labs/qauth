const AUTH_SERVER_URL = process.env['AUTH_SERVER_URL'];
const PORTAL_SESSION_SECRET = process.env['PORTAL_SESSION_SECRET'];
const PORTAL_SESSION_TTL = parseInt(process.env['PORTAL_SESSION_TTL'] ?? '900', 10);

if (!AUTH_SERVER_URL) {
  throw new Error('Missing required environment variable: AUTH_SERVER_URL');
}
if (!PORTAL_SESSION_SECRET) {
  throw new Error('Missing required environment variable: PORTAL_SESSION_SECRET');
}

export const env = {
  AUTH_SERVER_URL,
  PORTAL_SESSION_SECRET,
  PORTAL_SESSION_TTL,
} as const;
