import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

import { FLOW_COOKIE_NAME } from '@qauth-labs/shared-interaction-contract';
import type { FastifyReply, FastifyRequest } from 'fastify';

import { env } from '../../config/env';
import { readCookie } from './session-cookie';

/**
 * THE FLOW COOKIE (#592, ADR-019 Decision 6): what binds an interaction of
 * the Interaction API to the browser that started it.
 *
 * `__Host-qauth_flow`, set `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/` and
 * with no `Domain`, so only the realm's own auth host can set or read it and
 * no script can. Its value is a random secret per interaction; the
 * interaction record keeps only the secret's SHA-256 ({@link flowBindingOf}).
 * The interaction id alone reads a step's display data; anything more (its
 * personal data, an answer, a cancel) needs a secret whose hash the record
 * holds.
 *
 * A browser can hold more than one ceremony at a time (two tabs, two
 * clients), so the cookie carries up to {@link FLOW_COOKIE_MAX_BINDINGS}
 * secrets, newest last, joined by `.`. Starting an interaction adds one and
 * drops the oldest beyond the cap; finishing or cancelling one removes its
 * own; authenticating replaces it with a new one. A secret of an interaction
 * that has already ended matches no record, so a stale entry opens nothing.
 *
 * Unsigned: the secret is the whole credential and the server stores only its
 * hash, so a signature would add nothing. `Secure` follows
 * `SESSION_COOKIE_SECURE`, as every other `__Host-` cookie of the auth server
 * does: on by default, and off only on a plain-HTTP development stack, where a
 * browser refuses a `__Host-` cookie anyway.
 */

/** How many interactions one browser can hold at once. */
export const FLOW_COOKIE_MAX_BINDINGS = 4;

/** CSPRNG bytes per secret; 32 bytes are 43 base64url characters. */
const FLOW_SECRET_BYTES = 32;

/** Exactly what `randomBytes(32).toString('base64url')` produces. */
const FLOW_SECRET_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/** What separates the secrets in the cookie: never a base64url character. */
const SEPARATOR = '.';

/** A new flow secret. */
export function mintFlowSecret(): string {
  return randomBytes(FLOW_SECRET_BYTES).toString('base64url');
}

/** The binding an interaction record keeps for a secret: its SHA-256, base64url. */
export function flowBindingOf(secret: string): string {
  return createHash('sha256').update(secret).digest('base64url');
}

/**
 * The secrets the request's flow cookie carries, newest last: only
 * well-formed ones, each once, at most {@link FLOW_COOKIE_MAX_BINDINGS}. A
 * missing or unreadable cookie carries none.
 */
export function readFlowSecrets(request: FastifyRequest): string[] {
  let raw: string | undefined;
  try {
    raw = readCookie(request, FLOW_COOKIE_NAME);
  } catch {
    // `decodeURIComponent` throws on a malformed escape such as `%zz`: a
    // cookie no QAuth answer set, read as no cookie rather than a 500.
    return [];
  }
  return parseFlowSecrets(raw);
}

/** {@link readFlowSecrets} for a raw cookie value. */
export function parseFlowSecrets(raw: string | undefined): string[] {
  if (raw === undefined || raw.length === 0) return [];
  const secrets: string[] = [];
  for (const entry of raw.split(SEPARATOR)) {
    if (FLOW_SECRET_PATTERN.test(entry) && !secrets.includes(entry)) secrets.push(entry);
  }
  return secrets.slice(-FLOW_COOKIE_MAX_BINDINGS);
}

/**
 * The secret among `secrets` whose hash is `binding`, or `undefined`. Every
 * secret is hashed and compared timing-safely, whichever matches.
 */
export function matchFlowSecret(binding: string, secrets: readonly string[]): string | undefined {
  const expected = Buffer.from(binding, 'base64url');
  let match: string | undefined;
  for (const secret of secrets) {
    const actual = Buffer.from(flowBindingOf(secret), 'base64url');
    if (actual.length === expected.length && timingSafeEqual(actual, expected)) match = secret;
  }
  return match;
}

/**
 * The secrets after one change: `remove` dropped, `add` appended, and only
 * the newest {@link FLOW_COOKIE_MAX_BINDINGS} kept.
 */
export function nextFlowSecrets(
  secrets: readonly string[],
  change: { readonly add?: string; readonly remove?: string }
): string[] {
  const kept = secrets.filter((secret) => secret !== change.remove && secret !== change.add);
  if (change.add !== undefined) kept.push(change.add);
  return kept.slice(-FLOW_COOKIE_MAX_BINDINGS);
}

/**
 * Set the flow cookie to `secrets`, for `maxAgeSeconds`: the lifetime of the
 * newest interaction it binds. An empty list clears the cookie.
 */
export function setFlowCookie(
  reply: FastifyReply,
  secrets: readonly string[],
  maxAgeSeconds: number
): void {
  if (secrets.length === 0) {
    clearFlowCookie(reply);
    return;
  }
  const attrs = [
    `${FLOW_COOKIE_NAME}=${secrets.join(SEPARATOR)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${Math.max(1, Math.floor(maxAgeSeconds))}`,
  ];
  if (env.SESSION_COOKIE_SECURE) attrs.push('Secure');
  reply.header('Set-Cookie', attrs.join('; '));
}

/** Clear the flow cookie, when the browser holds no interaction any more. */
export function clearFlowCookie(reply: FastifyReply): void {
  const attrs = [`${FLOW_COOKIE_NAME}=`, 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=0'];
  if (env.SESSION_COOKIE_SECURE) attrs.push('Secure');
  reply.header('Set-Cookie', attrs.join('; '));
}
