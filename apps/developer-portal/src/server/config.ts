const AUTH_SERVER_URL = process.env['AUTH_SERVER_URL'];
const PORTAL_SESSION_SECRET = process.env['PORTAL_SESSION_SECRET'];
const PORTAL_SESSION_TTL = parseInt(process.env['PORTAL_SESSION_TTL'] ?? '900', 10);

// This module is server-only (it reads process.env and holds the session
// secret). The bundler can still pull it into a client chunk via the server
// actions, where process.env is empty — so only enforce the required vars on
// the server. Client code must use import.meta.env.VITE_AUTH_SERVER_URL.
if (import.meta.env.SSR) {
  if (!AUTH_SERVER_URL) {
    throw new Error('Missing required environment variable: AUTH_SERVER_URL');
  }
  if (!PORTAL_SESSION_SECRET) {
    throw new Error('Missing required environment variable: PORTAL_SESSION_SECRET');
  }
}

export const env = {
  AUTH_SERVER_URL,
  PORTAL_SESSION_SECRET,
  PORTAL_SESSION_TTL,
} as const;
