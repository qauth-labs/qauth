import { createHash } from 'node:crypto';

import { SERVICE_ROLE_NAMES, type ServiceRole } from '../schemas/service-roles';
import { type ConfigKey, KEY_DIGEST_CLASSES } from './types';

/**
 * THE CONFIGURATION DIGEST (ADR-019 Decision 8, issue #499).
 *
 * Every auth server node fingerprints its deployment-wide settings at boot
 * and compares the fingerprint with the nodes already running, so that two
 * nodes never serve different discovery documents or behave differently
 * because their environments differ. Which keys take part comes from the
 * registry: each key's digest class (`ConfigKey.digest`). Only `shared` keys
 * do, and a `secret` key never does, whatever its entry says.
 *
 * The digest is built from the parsed value of each key, so a key left unset
 * and a key set to its default compare equal, as do `true` and `TRUE` where
 * the schema reads both. A list compares in its order.
 *
 * What a node publishes is a SHA-256 digest per key and one over them all,
 * never a value. A hash hides nothing of a value with few possible values,
 * such as a switch, which is why only non-secret keys go in; the point of the
 * per-key digests is that a refusal can name the keys that differ without
 * either node revealing what it holds.
 */

/** What a node publishes of its settings. */
export interface ConfigurationDigest {
  /**
   * One digest over every key in {@link keys}: two nodes whose roles compare
   * the same keys and that hold the same values have the same one.
   */
  readonly digest: string;
  /** Each compared key's own digest, by key name. */
  readonly keys: Readonly<Record<string, string>>;
}

/** A digest built while a key it reads has no digest class. */
export class UnclassifiedConfigKeyError extends Error {
  readonly keys: readonly string[];

  constructor(keys: readonly string[]) {
    super(
      `These configuration keys have no digest class in the configuration key registry, so the configuration digest cannot tell whether they must match across nodes: ${keys.join(', ')}`
    );
    this.name = 'UnclassifiedConfigKeyError';
    this.keys = keys;
  }
}

/**
 * What is wrong with the digest classes of `keys`, one line per fault; empty
 * when every key is classified consistently:
 *
 * - every key has a class from `KEY_DIGEST_CLASSES`;
 * - a secret is `secret`, and only a secret is;
 * - only a `realm-seed` key is `realm-seed`, and one that is not secret is
 *   `realm-seed`, or `shared` while the server still reads its environment
 *   value at run time beside the realm's policy;
 * - only a `shared` key names roles, at least one, each a service role.
 */
export function digestClassificationProblems(keys: readonly ConfigKey[]): string[] {
  const problems: string[] = [];
  for (const key of keys) {
    const { name, digest } = key;
    if (digest === undefined) {
      problems.push(`${name} has no digest class`);
      continue;
    }
    if (!KEY_DIGEST_CLASSES.includes(digest)) {
      problems.push(`${name} has an unknown digest class ${JSON.stringify(digest)}`);
      continue;
    }
    if (key.secret !== (digest === 'secret')) {
      problems.push(
        key.secret
          ? `${name} is a secret, so its digest class is secret, not ${digest}`
          : `${name} is not a secret, so its digest class cannot be secret`
      );
    }
    if (!key.secret && digest === 'realm-seed' && key.role !== 'realm-seed') {
      problems.push(`${name} seeds no realm policy, so its digest class cannot be realm-seed`);
    } else if (
      !key.secret &&
      key.role === 'realm-seed' &&
      digest !== 'realm-seed' &&
      digest !== 'shared'
    ) {
      problems.push(
        `${name} seeds a realm policy, so its digest class is realm-seed, or shared while the server still reads it at run time, not ${digest}`
      );
    }
    if (key.digestRoles !== undefined) {
      if (digest !== 'shared') {
        problems.push(`${name} names digest roles but is not shared`);
      } else if (key.digestRoles.length === 0) {
        problems.push(`${name} names an empty list of digest roles`);
      } else {
        for (const role of key.digestRoles) {
          if (!(SERVICE_ROLE_NAMES as readonly string[]).includes(role)) {
            problems.push(`${name} names ${JSON.stringify(role)}, which is not a service role`);
          }
        }
      }
    }
  }
  return problems;
}

/**
 * The keys of `keys` a node with `roles` puts in its digest: every `shared`
 * key, but one that names digest roles only where the node holds one of
 * them, and never a secret.
 *
 * @throws UnclassifiedConfigKeyError when a key has no digest class
 */
export function digestedKeys(
  keys: readonly ConfigKey[],
  roles: readonly ServiceRole[]
): ConfigKey[] {
  const unclassified = keys.filter((key) => key.digest === undefined).map((key) => key.name);
  if (unclassified.length > 0) throw new UnclassifiedConfigKeyError(unclassified);
  return keys.filter(
    (key) =>
      key.digest === 'shared' &&
      !key.secret &&
      (key.digestRoles === undefined || key.digestRoles.some((role) => roles.includes(role)))
  );
}

/** The plain objects a parsed value may be: an object literal, or one with no prototype. */
function isPlainObject(value: object): value is Record<string, unknown> {
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

/**
 * One text for a parsed value, the same for equal values whatever the order
 * of an object's properties or a set's members. A value the digest cannot
 * read, such as a function or a buffer, throws, naming the key and never
 * the value.
 */
function canonical(name: string, value: unknown): string {
  if (value === undefined) return 'unset';
  if (value === null) return 'null';
  switch (typeof value) {
    case 'string':
      return JSON.stringify(value);
    case 'number':
      return Number.isFinite(value) ? JSON.stringify(value) : String(value);
    case 'boolean':
      return String(value);
    case 'bigint':
      return `${value.toString()}n`;
    case 'object':
      break;
    default:
      throw new TypeError(`The configuration digest cannot read the ${typeof value} of ${name}`);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonical(name, item)).join(',')}]`;
  }
  if (value instanceof Set) {
    return `set[${[...value]
      .map((item) => canonical(name, item))
      .sort()
      .join(',')}]`;
  }
  if (value instanceof Map) {
    return `map{${[...value]
      .map(
        ([entryKey, entryValue]) => `${canonical(name, entryKey)}:${canonical(name, entryValue)}`
      )
      .sort()
      .join(',')}}`;
  }
  if (value instanceof Date) return `date:${value.toISOString()}`;
  if (value instanceof URL) return `url:${JSON.stringify(value.href)}`;
  if (isPlainObject(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((property) => `${JSON.stringify(property)}:${canonical(name, value[property])}`)
      .join(',')}}`;
  }
  throw new TypeError(`The configuration digest cannot read the value of ${name}`);
}

function sha256(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

/**
 * The configuration digest of a node with `roles`: a digest of each key
 * {@link digestedKeys} picks from `keys`, read from `values` (the parsed
 * environment, by key name), and one over them all. Neither depends on the
 * order of `keys` or of `values`.
 *
 * @throws UnclassifiedConfigKeyError when a key of `keys` has no digest class
 * @throws TypeError when a compared value is neither JSON-like data nor a
 *   set, map, date or URL of it
 */
export function configurationDigest(
  keys: readonly ConfigKey[],
  values: Readonly<Record<string, unknown>>,
  roles: readonly ServiceRole[]
): ConfigurationDigest {
  const perKey: Record<string, string> = {};
  for (const key of digestedKeys(keys, roles)) {
    perKey[key.name] = sha256(`${key.name}=${canonical(key.name, values[key.name])}`);
  }
  const names = Object.keys(perKey).sort();
  return {
    digest: sha256(names.map((name) => `${name}:${perKey[name]}\n`).join('')),
    keys: Object.freeze(Object.fromEntries(names.map((name) => [name, perKey[name] as string]))),
  };
}

/**
 * The keys whose digests differ between two nodes, sorted by name: only the
 * keys both nodes compare, so a key one node's roles leave out never counts.
 */
export function differingKeys(
  ours: Readonly<Record<string, string>>,
  theirs: Readonly<Record<string, string>>
): string[] {
  return Object.keys(ours)
    .filter((name) => Object.hasOwn(theirs, name) && theirs[name] !== ours[name])
    .sort();
}
