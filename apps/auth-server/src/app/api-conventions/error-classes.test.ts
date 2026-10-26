/// <reference types="vitest/globals" />
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

import { SsfRequestError } from '@qauth-labs/fastify-plugin-ssf';
import * as sharedErrors from '@qauth-labs/shared-errors';
import { InsufficientScopeError, InvalidDpopProofError } from '@qauth-labs/shared-errors';

import { SignInRequiredError } from '../helpers/sign-in-required';
import { SsfNotFoundError, SsfStreamExistsError } from '../helpers/ssf-errors';
import {
  APP_ERROR_CLASSES,
  describeProblem,
  ERROR_CLASSES,
  errorClassEntryOf,
} from './error-classes';
import { OAUTH_ERROR_CODES } from './oauth-error';
import { PROBLEM_CODES, PROBLEM_TYPE_BASE } from './problem';

/**
 * The error registry (#513): every domain error class has one entry, and the
 * entry agrees with the class.
 */

/** A class of the package, whatever its constructor takes. */
type ErrorClass = new (...args: never[]) => Error;

/** Every error class `@qauth-labs/shared-errors` exports. */
const EXPORTED_CLASSES: [string, ErrorClass][] = Object.entries(
  sharedErrors as Record<string, unknown>
)
  .filter(([, value]) => typeof value === 'function' && value.prototype instanceof Error)
  .map(([name, value]) => [name, value as ErrorClass]);

/** An instance of `errorClass`, built the way the server builds it. */
function instanceOf(errorClass: ErrorClass): Error {
  if (errorClass === InvalidDpopProofError) {
    // The only class whose status depends on where it is thrown. A problem
    // route meets it at a resource, where it is a 401 (RFC 9449 §7.1).
    return new InvalidDpopProofError(undefined, { atResource: true });
  }
  if (errorClass === InsufficientScopeError) {
    // The only class that needs an argument: the scopes its challenge names.
    return new InsufficientScopeError(['scope:read']);
  }
  return new (errorClass as new () => Error)();
}

describe('the error registry (#513)', () => {
  it('finds error classes to check', () => {
    expect(EXPORTED_CLASSES.length).toBeGreaterThanOrEqual(30);
  });

  it.each(EXPORTED_CLASSES)('has an entry for %s', (_name, errorClass) => {
    expect(ERROR_CLASSES.filter((entry) => entry.errorClass === errorClass)).toHaveLength(1);
  });

  it('lists no class the package does not export', () => {
    const exported = new Set<unknown>(EXPORTED_CLASSES.map(([, errorClass]) => errorClass));
    for (const entry of ERROR_CLASSES) expect(exported.has(entry.errorClass)).toBe(true);
  });

  it.each(EXPORTED_CLASSES)('sends %s with the status the class declares', (_name, errorClass) => {
    const error = instanceOf(errorClass) as Error & { statusCode: number };
    const entry = errorClassEntryOf(error);

    if (entry === undefined) throw new Error('no entry');
    expect(entry.errorClass).toBe(errorClass);
    expect(PROBLEM_CODES[entry.code].status).toBe(error.statusCode);
  });

  it.each(EXPORTED_CLASSES)(
    "publishes %s's own code, lower-cased, unless it is a server-side failure",
    (_name, errorClass) => {
      const error = instanceOf(errorClass) as Error & { code: string; statusCode: number };
      const code = errorClassEntryOf(error)?.code;

      if (error.statusCode >= 500) {
        expect(['internal_error', 'service_unavailable']).toContain(code);
      } else {
        expect(code).toBe(error.code.toLowerCase());
      }
    }
  );

  it('answers an OAuth error class with its own token on an OAuth protocol endpoint', () => {
    for (const entry of ERROR_CLASSES) {
      const error = instanceOf(entry.errorClass as ErrorClass);
      if (Object.hasOwn(OAUTH_ERROR_CODES, error.message)) {
        expect(entry.oauthError, error.name).toBe(error.message);
      }
    }
  });

  it('gives every code a type URI under the problem types page and a title', () => {
    const slugs = new Set<string>();
    for (const code of Object.keys(PROBLEM_CODES) as (keyof typeof PROBLEM_CODES)[]) {
      const { type, title, status } = describeProblem(code);
      const slug = type.slice(PROBLEM_TYPE_BASE.length);

      expect(type.startsWith(PROBLEM_TYPE_BASE)).toBe(true);
      expect(slug).toMatch(/^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/);
      expect(slug).toBe(code.replaceAll('_', '-'));
      expect(title.length).toBeGreaterThan(0);
      expect(status).toBe(PROBLEM_CODES[code].status);
      slugs.add(slug);
    }
    expect(slugs.size).toBe(Object.keys(PROBLEM_CODES).length);
  });

  it('lists no app class twice, and none the package exports', () => {
    const exported = new Set<unknown>(EXPORTED_CLASSES.map(([, errorClass]) => errorClass));
    const listed = APP_ERROR_CLASSES.map((entry) => entry.errorClass);

    expect(new Set(listed).size).toBe(listed.length);
    for (const errorClass of listed) expect(exported.has(errorClass)).toBe(false);
  });

  it.each(APP_ERROR_CLASSES.map((entry) => [entry.errorClass.name, entry] as const))(
    'sends the app class %s with a code published for the status it carries',
    (_name, entry) => {
      const error = new (entry.errorClass as new () => Error & { statusCode: number })();

      expect(errorClassEntryOf(error)).toBe(entry);
      expect(PROBLEM_CODES[entry.code].status).toBe(error.statusCode);
      expect(Object.hasOwn(OAUTH_ERROR_CODES, entry.oauthError)).toBe(true);
    }
  );

  it.each([
    // A cookie-authenticated route without a browser session (#513).
    [SignInRequiredError, 'unauthorized', 401],
    // The SSF transmitter's refusals (SSF 1.0 §8.1 defines no error body).
    [SsfRequestError, 'bad_request', 400],
    [SsfNotFoundError, 'not_found', 404],
    [SsfStreamExistsError, 'conflict', 409],
  ] as const)('answers %o with %s (%i)', (errorClass, code, status) => {
    const { code: entryCode } = errorClassEntryOf(new errorClass()) ?? {};

    expect(entryCode).toBe(code);
    expect(describeProblem(code)).toMatchObject({
      status,
      type: `${PROBLEM_TYPE_BASE}${code.replaceAll('_', '-')}`,
    });
  });

  it('has an entry for every error class of the app that carries a status', () => {
    // A class a route defines and throws with a `statusCode` reaches the
    // error handler. Without an entry it answers the code of its status,
    // which is right only for a class whose status varies by throw site.
    const APP_DIR = join(__dirname, '..');
    const STATUS_DECIDES = new Set(['WalletLinkRefusal']);
    const sources = (dir: string): string[] =>
      readdirSync(dir).flatMap((name) => {
        const path = join(dir, name);
        if (statSync(path).isDirectory()) return sources(path);
        return name.endsWith('.ts') && !name.endsWith('.test.ts') ? [path] : [];
      });
    const listed = new Set(APP_ERROR_CLASSES.map((entry) => entry.errorClass.name));
    // A class body: empty on its line, or up to the brace that closes it at
    // the start of a line.
    const declaration = /class (\w+) extends Error \{(\}|[\s\S]*?\n\})/g;

    const missing: string[] = [];
    let found = 0;
    for (const path of sources(APP_DIR)) {
      for (const [, name, body] of readFileSync(path, 'utf8').matchAll(declaration)) {
        if (!/\bstatusCode\b/.test(body ?? '')) continue;
        found += 1;
        if (!listed.has(name ?? '') && !STATUS_DECIDES.has(name ?? '')) {
          missing.push(`${relative(APP_DIR, path)}: ${name}`);
        }
      }
    }

    expect(found).toBeGreaterThanOrEqual(4);
    expect(missing).toEqual([]);
  });

  it('reads a subclass by its own entry when it has one, else by its parent', () => {
    class LocalNotFound extends sharedErrors.NotFoundError {}
    expect(errorClassEntryOf(new LocalNotFound('Thing', 'x'))?.code).toBe('not_found');
    expect(errorClassEntryOf(new Error('plain'))).toBeUndefined();
    expect(errorClassEntryOf({ statusCode: 400 })).toBeUndefined();
  });
});
