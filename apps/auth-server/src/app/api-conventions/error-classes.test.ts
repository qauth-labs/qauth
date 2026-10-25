/// <reference types="vitest/globals" />
import * as sharedErrors from '@qauth-labs/shared-errors';
import { InvalidDpopProofError } from '@qauth-labs/shared-errors';

import { describeProblem, ERROR_CLASSES, errorClassEntryOf } from './error-classes';
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

  it('reads a subclass by its own entry when it has one, else by its parent', () => {
    class LocalNotFound extends sharedErrors.NotFoundError {}
    expect(errorClassEntryOf(new LocalNotFound('Thing', 'x'))?.code).toBe('not_found');
    expect(errorClassEntryOf(new Error('plain'))).toBeUndefined();
    expect(errorClassEntryOf({ statusCode: 400 })).toBeUndefined();
  });
});
