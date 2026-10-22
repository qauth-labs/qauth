/**
 * The payload rules (ADR-011 §8, ADR-017 §11; issue #456), and the scanner
 * that enforces them. Those two records wrote the rules for the audit table;
 * they apply to every event's `data`:
 *
 * 1. Ids, not names or addresses. A type that needs a name, an email address,
 *    a phone number or an IP address declares that field in its registry
 *    entry (`personalData`); no other type carries one.
 * 2. Never a password, code, OTP, token, key, assertion, signature, cookie,
 *    secret, or a set-up or reset link. There is no exception.
 * 3. An identifier that must stay hidden, such as the address a failed
 *    sign-in typed, is a keyed HMAC (`...Hmac`), never the value and never a
 *    plain hash, which a dictionary reverses.
 *
 * The scanner reads field names, not meanings, so it is a net, not a proof.
 * It splits each name into words (`apiKeyId` → `api`, `key`, `id`). A name
 * with a secret word is refused, unless its last word says the field holds an
 * identifier, a type or a count of the thing (`apiKeyId`, `tokenType`,
 * `revokedTokenCount`), never the thing itself. Values are read too: a string
 * shaped like a JWT, a JWS or JWE in compact form, or a PEM block is refused
 * wherever it sits.
 */

/** Which rule a finding breaks. */
export type PayloadRule = 'secret_field' | 'personal_data_field' | 'secret_value';

/** One place in a payload, or in a schema, that breaks a payload rule. */
export interface PayloadFinding {
  /** A JSON Pointer (RFC 6901) to the field or the value. */
  readonly path: string;
  readonly rule: PayloadRule;
  readonly message: string;
}

export interface PayloadScanOptions {
  /**
   * Field names this type may carry although they name personal data
   * (rule 1). Secret fields (rule 2) can never be allowed.
   */
  readonly personalData?: readonly string[];
}

/** Words that name a secret (rule 2). */
export const SECRET_WORDS: ReadonlySet<string> = new Set([
  'password',
  'passwords',
  'passwd',
  'passphrase',
  'pwd',
  'pin',
  'secret',
  'secrets',
  'token',
  'tokens',
  'code',
  'codes',
  'otp',
  'otps',
  'totp',
  'hotp',
  'key',
  'keys',
  'assertion',
  'assertions',
  'signature',
  'signatures',
  'cookie',
  'cookies',
  'link',
  'links',
  'url',
  'urls',
  'uri',
  'uris',
  'href',
  // Token and key formats, and credentials that are themselves secrets.
  'jwt',
  'jwts',
  'jwk',
  'jwks',
  'bearer',
  'credential',
  'credentials',
  'presentation',
  'presentations',
  'seed',
  'proof',
]);

/**
 * Secret words that are also caught inside a longer word, for names written
 * without a separator (`accesstoken`, `clientsecret`, `apikey`). Only stems
 * that no harmless word contains: `code` (`encode`), `key` (`monkey`) and
 * `link` (`linked`) alone are matched as whole words only.
 */
export const SECRET_STEMS: readonly string[] = [
  'password',
  'passwd',
  'passphrase',
  'secret',
  'token',
  'assertion',
  'jwt',
  'apikey',
  'privatekey',
  'signingkey',
];

/** Words that name a person or an address (rule 1). */
export const PERSONAL_DATA_WORDS: ReadonlySet<string> = new Set([
  'email',
  'emails',
  'mail',
  'phone',
  'phones',
  'address',
  'addresses',
  'ip',
  'ips',
  'name',
  'names',
  'username',
  'firstname',
  'lastname',
  'fullname',
  'surname',
  'birthdate',
  'birthday',
  // What a person typed to name their account: `assertedIdentifier`,
  // `loginHint`. Carried as a keyed HMAC (`identifierHmac`), never in clear.
  'identifier',
  'login',
]);

/**
 * Last words that say a field holds an identifier, a type or a count of the
 * thing its other words name, so `apiKeyId` and `tokenType` are not secrets.
 */
export const DESCRIPTOR_WORDS: ReadonlySet<string> = new Set([
  'id',
  'ids',
  'type',
  'types',
  'count',
]);

/**
 * Last words that say a personal-data field is already hidden (rule 3) or is
 * an identifier: `emailHmac`, `ipCount`.
 */
const HIDDEN_WORDS: ReadonlySet<string> = new Set([...DESCRIPTOR_WORDS, 'hmac']);

/**
 * A compact JWT, JWS or JWE anywhere in a string: inside an SD-JWT
 * (`<jwt>~<disclosure>~`), after `Bearer `, or with whitespace around it.
 */
const COMPACT_JOSE = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/;

/** A PEM block: a key, a certificate or anything else armoured. */
const PEM = /-----BEGIN [A-Z0-9 ]+-----/;

/** Split a field name into lower-case words: `apiKeyID` → `api`, `key`, `id`. */
export function fieldNameWords(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/)
    .filter((word) => word.length > 0)
    .map((word) => word.toLowerCase());
}

/**
 * Classify one field name.
 *
 * @returns the rule the name breaks, or `null` when it is allowed
 */
export function classifyFieldName(
  name: string,
  options: PayloadScanOptions = {}
): Exclude<PayloadRule, 'secret_value'> | null {
  const words = fieldNameWords(name);
  if (words.length === 0) return null;
  const last = words[words.length - 1];

  const describesSecret = words.length > 1 && DESCRIPTOR_WORDS.has(last);
  const secretWord = words.some((word) => SECRET_WORDS.has(word));
  const secretStem = words.some(
    (word) => !SECRET_WORDS.has(word) && SECRET_STEMS.some((stem) => word.includes(stem))
  );
  if ((secretWord || secretStem) && !describesSecret) return 'secret_field';

  const personal = words.some((word) => PERSONAL_DATA_WORDS.has(word));
  const hidden = words.length > 1 && HIDDEN_WORDS.has(last);
  if (personal && !hidden && !(options.personalData ?? []).includes(name)) {
    return 'personal_data_field';
  }
  return null;
}

const escapePointer = (segment: string) => segment.replace(/~/g, '~0').replace(/\//g, '~1');

function fieldFinding(path: string, name: string, rule: Exclude<PayloadRule, 'secret_value'>) {
  return {
    path,
    rule,
    message:
      rule === 'secret_field'
        ? `"${name}" names a secret; an event never carries a password, code, OTP, token, key, assertion, signature, cookie, secret or link`
        : `"${name}" names personal data; carry an id or an HMAC instead, or list the field in the type's personalData`,
  } satisfies PayloadFinding;
}

function scan(value: unknown, readNames: boolean, options: PayloadScanOptions): PayloadFinding[] {
  const findings: PayloadFinding[] = [];
  const visit = (node: unknown, path: string) => {
    if (typeof node === 'string') {
      if (COMPACT_JOSE.test(node) || PEM.test(node)) {
        findings.push({
          path: path || '/',
          rule: 'secret_value',
          message: 'the value is shaped like a token, a signed or encrypted object, or a key',
        });
      }
      return;
    }
    if (Array.isArray(node)) {
      node.forEach((item, index) => visit(item, `${path}/${index}`));
      return;
    }
    if (typeof node === 'object' && node !== null) {
      for (const [key, child] of Object.entries(node)) {
        const childPath = `${path}/${escapePointer(key)}`;
        const rule = readNames ? classifyFieldName(key, options) : null;
        if (rule) findings.push(fieldFinding(childPath, key, rule));
        visit(child, childPath);
      }
    }
  };
  visit(value, '');
  return findings;
}

/**
 * Scan a payload (an event's `data`, or any JSON value) for fields and values
 * that break the payload rules.
 *
 * @returns every finding, in document order; empty when the payload is clean
 */
export function scanPayload(value: unknown, options: PayloadScanOptions = {}): PayloadFinding[] {
  return scan(value, true, options);
}

/**
 * Scan only the values: a string shaped like a token or a key, wherever it
 * sits. For the envelope's own members, whose names are fixed and some of
 * which (`request.ip`) name personal data on purpose.
 */
export function scanValues(value: unknown): PayloadFinding[] {
  return scan(value, false, {});
}

const SUBSCHEMA_KEYS = ['items', 'additionalProperties', 'not', 'if', 'then', 'else'] as const;
const SUBSCHEMA_LIST_KEYS = ['anyOf', 'oneOf', 'allOf', 'prefixItems'] as const;
const SUBSCHEMA_MAP_KEYS = ['$defs', 'definitions', 'patternProperties'] as const;

/**
 * Scan a JSON Schema for declared fields whose names break the payload rules.
 * Every `properties` key is read, at any depth: inside arrays, unions and
 * definitions too.
 *
 * @returns every finding; the path points into the schema
 */
export function scanJsonSchema(
  schema: unknown,
  options: PayloadScanOptions = {}
): PayloadFinding[] {
  const findings: PayloadFinding[] = [];
  const visit = (node: unknown, path: string) => {
    if (typeof node !== 'object' || node === null || Array.isArray(node)) return;
    const record = node as Record<string, unknown>;
    // A record whose keys are a fixed set (`z.record(z.enum([...]), ...)`)
    // declares those keys as field names too.
    const names = record['propertyNames'];
    if (typeof names === 'object' && names !== null) {
      const { enum: values, const: single } = names as Record<string, unknown>;
      const listed = Array.isArray(values) ? values : single === undefined ? [] : [single];
      for (const key of listed.filter((value): value is string => typeof value === 'string')) {
        const rule = classifyFieldName(key, options);
        if (rule) findings.push(fieldFinding(`${path}/propertyNames`, key, rule));
      }
    }
    const properties = record['properties'];
    if (typeof properties === 'object' && properties !== null) {
      for (const [key, child] of Object.entries(properties)) {
        const childPath = `${path}/properties/${escapePointer(key)}`;
        const rule = classifyFieldName(key, options);
        if (rule) findings.push(fieldFinding(childPath, key, rule));
        visit(child, childPath);
      }
    }
    for (const key of SUBSCHEMA_KEYS) visit(record[key], `${path}/${key}`);
    for (const key of SUBSCHEMA_LIST_KEYS) {
      const list = record[key];
      if (Array.isArray(list)) list.forEach((item, i) => visit(item, `${path}/${key}/${i}`));
    }
    for (const key of SUBSCHEMA_MAP_KEYS) {
      const map = record[key];
      if (typeof map === 'object' && map !== null) {
        for (const [name, child] of Object.entries(map)) {
          visit(child, `${path}/${key}/${escapePointer(name)}`);
        }
      }
    }
  };
  visit(schema, '');
  return findings;
}
