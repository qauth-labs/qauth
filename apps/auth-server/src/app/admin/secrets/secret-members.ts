import { z } from 'zod';

/**
 * THE SECRET MEMBERS OF A SECURITY OPERATION (ADR-019 Decision 7, issue #984).
 *
 * An approval keeps `op_hash`, the SHA-256 of the operation's canonical
 * request with a nonce the server draws, and the nonce beside it until the
 * approval closes (#901). A copy of the approvals table taken while one is
 * open (a dump, a replica, a WAL archive) holds both, and so does the admin
 * audit log's `request_digest`: whoever has it can test a guessed body
 * against `op_hash` offline, and a secret that can be guessed, such as a short
 * password, would be exposed. So a security operation takes a secret only
 * sealed: encrypted for the realm, for that operation and that member, by
 * `secrets.seal` before the request is filed. No guess reaches a ciphertext.
 *
 * The listener cannot tell a secret from a plain string by its schema, so an
 * operation declares the members of its body that carry one
 * (`secretMembers` in its definition, `helpers/admin-operations.ts`), and the
 * admin listener refuses to boot its route unless the body schema holds each
 * of them to {@link SEALED_VALUE_SCHEMA}.
 *
 * A declared member is a JSON Pointer (RFC 6901) into the body, in which the
 * token `*` stands for every member of a record or every item of an array:
 * `/secrets/*` is each value of the record `secrets`. One concrete member,
 * as a value is sealed for it, is a pointer without `*`:
 * `/secrets/clientSecret`.
 *
 * This module is a leaf: it imports nothing of the admin API, so the registry
 * and the pipeline can both read it.
 */

/**
 * A data-at-rest ciphertext, `v1.<kid>.<iv>.<ciphertext>`, as the signer
 * writes one: a 96-bit IV (16 base64url characters) and a ciphertext of at
 * least its 128-bit tag (22).
 */
const CIPHERTEXT_PATTERN = /^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22,}$/;

/** The longest value `secrets.seal` seals, in UTF-16 code units. */
export const MAX_SEALED_SECRET_LENGTH = 8192;

/**
 * The longest sealed value: a secret of {@link MAX_SEALED_SECRET_LENGTH}
 * (at most 24 KiB as UTF-8), encrypted and base64url-encoded, with room for
 * its key id and IV.
 */
export const MAX_SEALED_VALUE_LENGTH = 48 * 1024;

/** The longest member pointer a value is sealed for. */
export const MAX_SECRET_MEMBER_LENGTH = 768;

/** The token of a declared member that stands for every member of a record or item of an array. */
export const EVERY_MEMBER = '*';

/**
 * THE SEALED-VALUE SCHEMA: the one schema of a secret member of a security
 * operation's body, `{ "sealed": "v1.…" }`, as `secrets.seal` answers it. A
 * route uses it as it is, or `.nullable()` / `.optional()` (a member a request
 * may clear or leave out); a copy that only adds metadata (`.meta()`,
 * `.describe()`) is the same schema. Any other schema, a plain string
 * included, fails the admin listener's boot for a member the operation
 * declares secret.
 */
export const SEALED_VALUE_SCHEMA = z
  .strictObject({
    sealed: z.string().max(MAX_SEALED_VALUE_LENGTH).regex(CIPHERTEXT_PATTERN).meta({
      description:
        'The value, encrypted by secrets.seal for this member of this operation in the realm.',
    }),
  })
  .meta({
    description:
      'A secret, sealed with secrets.seal for this member of this operation in the realm: never the value itself.',
  });

/** A sealed value, as {@link SEALED_VALUE_SCHEMA} parses one. */
export type SealedValue = z.infer<typeof SEALED_VALUE_SCHEMA>;

/** An RFC 6901 reference token as written: `~` only as `~0` or `~1`. */
const ESCAPED_TOKEN = /^(?:[^~]|~[01])*$/;

/** A reference token written into a pointer: `~` and `/` escaped (RFC 6901). */
export const pointerToken = (key: string): string => key.replace(/~/g, '~0').replace(/\//g, '~1');

/** Whether `text` holds a C0 control character or DEL. */
function hasControlCharacter(text: string): boolean {
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

/** The pointer of `tokens`: each escaped, each after a `/`. */
export function memberPointer(tokens: readonly string[]): string {
  return tokens.map((token) => `/${pointerToken(token)}`).join('');
}

/**
 * The reference tokens of `pointer`, unescaped, or `undefined` when it is not
 * a pointer to a member: it starts with `/`, is at most
 * {@link MAX_SECRET_MEMBER_LENGTH} long, and no token is empty or holds a
 * stray `~` or a control character.
 */
export function memberTokens(pointer: unknown): string[] | undefined {
  if (
    typeof pointer !== 'string' ||
    !pointer.startsWith('/') ||
    pointer.length > MAX_SECRET_MEMBER_LENGTH ||
    hasControlCharacter(pointer)
  ) {
    return undefined;
  }
  const raw = pointer.slice(1).split('/');
  if (raw.some((token) => token === '' || !ESCAPED_TOKEN.test(token))) return undefined;
  return raw.map((token) => token.replace(/~1/g, '/').replace(/~0/g, '~'));
}

/** Whether `pattern` is a declared secret member: a member pointer, `*` tokens allowed. */
export function isSecretMemberPattern(pattern: unknown): pattern is string {
  return memberTokens(pattern) !== undefined;
}

/** Whether `member` is one concrete member a value is sealed for: a member pointer with no `*` token. */
export function isSecretMember(member: unknown): member is string {
  const tokens = memberTokens(member);
  return tokens !== undefined && !tokens.includes(EVERY_MEMBER);
}

/** Whether the concrete `member` is one of the members `pattern` declares. */
export function secretMemberMatches(pattern: string, member: string): boolean {
  const want = memberTokens(pattern);
  const have = memberTokens(member);
  if (want === undefined || have === undefined || have.includes(EVERY_MEMBER)) return false;
  return (
    want.length === have.length &&
    want.every((token, index) => token === EVERY_MEMBER || token === have[index])
  );
}

/** What this module reads of a Zod schema's definition. */
interface SchemaDefinition {
  readonly type?: unknown;
  readonly innerType?: unknown;
  readonly shape?: unknown;
  readonly valueType?: unknown;
  readonly element?: unknown;
}

/**
 * The definition of a Zod 4 schema, or `undefined` for anything else. A copy
 * that only adds metadata (`.meta()`, `.describe()`) shares its original's
 * definition; one that adds a check or changes its shape has its own.
 */
function definitionOf(schema: unknown): SchemaDefinition | undefined {
  if (typeof schema !== 'object' || schema === null) return undefined;
  const zod: unknown = (schema as { _zod?: unknown })._zod;
  if (typeof zod !== 'object' || zod === null) return undefined;
  const def: unknown = (zod as { def?: unknown }).def;
  return typeof def === 'object' && def !== null ? (def as SchemaDefinition) : undefined;
}

/** Wrappers a walk passes through on the way to a member: they change nothing it holds. */
const CONTAINER_WRAPPERS: ReadonlySet<unknown> = new Set([
  'optional',
  'nullable',
  'readonly',
  'default',
  'prefault',
  'nonoptional',
]);

/** Wrappers a secret member may carry around the sealed-value schema. */
const MEMBER_WRAPPERS: ReadonlySet<unknown> = new Set(['optional', 'nullable']);

/** `schema` with the wrappers of `kinds` taken off. */
function unwrapped(schema: unknown, kinds: ReadonlySet<unknown>): unknown {
  let current = schema;
  for (let depth = 0; depth < 16; depth += 1) {
    const def = definitionOf(current);
    if (def === undefined || !kinds.has(def.type)) return current;
    current = def.innerType;
  }
  return current;
}

/**
 * Why the body schema `body` does not hold the secret member `pattern` to
 * {@link SEALED_VALUE_SCHEMA}, or `undefined` when it does. The walk follows
 * the pointer through Zod objects (by member name), records (any token) and
 * arrays (`*`), through the wrappers that change nothing the member holds
 * (`optional`, `nullable`, `readonly`, `default`); any other schema on the way
 * (a union, a pipe or transform, a lazy schema) is refused, since the check
 * could not say what reaches the handler. At the member, the schema is the
 * sealed one, as it is or `nullable()` / `optional()`.
 */
export function secretMemberSchemaProblem(body: unknown, pattern: string): string | undefined {
  const tokens = memberTokens(pattern);
  if (tokens === undefined) {
    return `${JSON.stringify(pattern)} is not a member pointer (RFC 6901)`;
  }
  let node: unknown = body;
  for (const [index, token] of tokens.entries()) {
    node = unwrapped(node, CONTAINER_WRAPPERS);
    const def = definitionOf(node);
    const at = index === 0 ? 'the body' : memberPointer(tokens.slice(0, index));
    if (def?.type === 'object') {
      const shape = (def.shape ?? {}) as Record<string, unknown>;
      if (token === EVERY_MEMBER) {
        return `${at} is an object, so ${pattern} names each of its secret members, not *`;
      }
      if (!Object.hasOwn(shape, token)) {
        return `the body schema has no member ${memberPointer(tokens.slice(0, index + 1))}`;
      }
      node = shape[token];
    } else if (def?.type === 'record') {
      node = def.valueType;
    } else if (def?.type === 'array' && token === EVERY_MEMBER) {
      node = def.element;
    } else {
      return `the schema of ${at} is ${def === undefined ? 'not a Zod schema' : `a Zod ${String(def.type)}`}, through which the check cannot follow ${pattern}`;
    }
  }
  const member = definitionOf(unwrapped(node, MEMBER_WRAPPERS));
  if (member === undefined || member !== definitionOf(SEALED_VALUE_SCHEMA)) {
    return `the schema of ${pattern} is not the sealed-value schema (SEALED_VALUE_SCHEMA), so a secret could reach it in the clear`;
  }
  return undefined;
}

/** One sealed value a parsed body holds at a declared secret member. */
export interface SealedMember {
  /** The concrete member, a pointer without `*`. */
  readonly member: string;
  readonly sealed: string;
}

/**
 * Every sealed value `body`, as its route parsed it, holds at the members
 * `patterns` declare: each `{ sealed }` found there, with its concrete member.
 * A member the body leaves out, or that is `null`, holds none.
 */
export function sealedMembersOf(body: unknown, patterns: readonly string[]): SealedMember[] {
  const found: SealedMember[] = [];
  for (const pattern of patterns) {
    const tokens = memberTokens(pattern);
    if (tokens === undefined) continue;
    const walk = (value: unknown, index: number, path: readonly string[]): void => {
      if (typeof value !== 'object' || value === null) return;
      if (index === tokens.length) {
        const sealed: unknown = (value as { sealed?: unknown }).sealed;
        if (!Array.isArray(value) && typeof sealed === 'string') {
          found.push({ member: memberPointer(path), sealed });
        }
        return;
      }
      const token = tokens[index];
      const keys =
        token === EVERY_MEMBER ? Object.keys(value) : Object.hasOwn(value, token) ? [token] : [];
      for (const key of keys) {
        walk((value as Record<string, unknown>)[key], index + 1, [...path, key]);
      }
    };
    walk(body, 0, []);
  }
  return found;
}
