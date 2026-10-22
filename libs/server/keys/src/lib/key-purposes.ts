/**
 * The fixed list of key purposes (ADR-019 Decision 9, issue #463).
 *
 * `realm_keys.purpose` stores one of these names, and every key a realm holds
 * belongs to exactly one of them. The list is part of the wire-level promise
 * once keys exist: a stored row names its purpose, and the purpose is bound
 * into the associated data that seals its material (`encodeKeyAad`). A purpose
 * that has no consumer yet still has its entry here, so its name and rules are
 * settled before the first key of it is stored.
 */

/**
 * What a key does.
 *
 * - `signing` — an asymmetric key pair that signs; its public half verifies.
 * - `encryption` — an asymmetric key-agreement pair (ECDH-ES): peers encrypt to
 *   the public half, and the private half decrypts.
 * - `symmetric` — a 32-byte secret, used for an HMAC or for AES-256-GCM. It has
 *   no public half and is never published.
 */
export type KeyKind = 'signing' | 'encryption' | 'symmetric';

/**
 * Every algorithm a stored key can be for, as `realm_keys.algorithm` stores it.
 *
 * The JOSE names (RFC 7518, RFC 8037, RFC 9964) are used throughout, also for
 * the symmetric secrets that never appear in a JOSE object: `HS256` is
 * HMAC-SHA-256 and `A256GCM` is AES-256-GCM.
 */
export const KEY_ALGORITHMS = [
  'EdDSA',
  'RS256',
  'ES256',
  'ML-DSA-65',
  'ECDH-ES',
  'HS256',
  'A256GCM',
] as const;

/** An algorithm a stored key can be for. See {@link KEY_ALGORITHMS}. */
export type KeyAlgorithm = (typeof KEY_ALGORITHMS)[number];

/** The kind of key each algorithm needs. A purpose lists algorithms of its own kind only. */
export const KEY_ALGORITHM_KINDS: Readonly<Record<KeyAlgorithm, KeyKind>> = Object.freeze({
  EdDSA: 'signing',
  RS256: 'signing',
  ES256: 'signing',
  'ML-DSA-65': 'signing',
  'ECDH-ES': 'encryption',
  HS256: 'symmetric',
  A256GCM: 'symmetric',
});

/** The default rotation period, in days (ADR-019 Decision 9). The operator can change it. */
export const DEFAULT_KEY_ROTATION_PERIOD_DAYS = 90;

/**
 * How a purpose's keys rotate by default.
 *
 * - `automatic` — the rotation job (#542) replaces the key every `periodDays`,
 *   with the overlap ADR-019 Decision 9 describes.
 * - `manual` — the key changes only when someone asks. Used where a party
 *   outside this deployment holds a copy of the key or of its public half, so
 *   a scheduled change would break that party without notice.
 */
export type KeyRotationDefault =
  { readonly mode: 'automatic'; readonly periodDays: number } | { readonly mode: 'manual' };

const AUTOMATIC: KeyRotationDefault = Object.freeze({
  mode: 'automatic',
  periodDays: DEFAULT_KEY_ROTATION_PERIOD_DAYS,
});
const MANUAL: KeyRotationDefault = Object.freeze({ mode: 'manual' });

/** The rules of one key purpose. */
export interface KeyPurposeDefinition {
  /** What the purpose's keys are for, in one line. */
  readonly description: string;
  /** What its keys do. Every algorithm in {@link algorithms} is of this kind. */
  readonly kind: KeyKind;
  /** The algorithms its keys may have. */
  readonly algorithms: readonly KeyAlgorithm[];
  /** The algorithm a new key gets when the caller names none. One of {@link algorithms}. */
  readonly defaultAlgorithm: KeyAlgorithm;
  /**
   * Whether each key belongs to one owner inside the realm, named by
   * `realm_keys.scope_id`, such as a webhook subscription. A scoped purpose
   * needs a scope id; an unscoped one refuses it.
   */
  readonly scoped: boolean;
  /**
   * Whether the public half is stored in `realm_public_keys`, where roles that
   * hold no private key can read it. Where a published key then appears (the
   * realm JWKS, an entity configuration, client metadata) is its consumer's
   * decision. Symmetric purposes are never published.
   */
  readonly published: boolean;
  /** How its keys rotate unless the operator says otherwise. */
  readonly rotation: KeyRotationDefault;
  /**
   * The algorithm of the second key of a hybrid pair (ADR-005). With hybrid
   * signing on, a new key of {@link defaultAlgorithm} is created together with
   * a key of this algorithm, and both share one `pair_id`. A key of this
   * algorithm is never created on its own.
   */
  readonly hybridCompanion?: KeyAlgorithm;
  /**
   * Whether only a federation-operator deployment may create the purpose's
   * keys. Every other deployment refuses them (ADR-019 Decision 9).
   */
  readonly federationOperatorOnly?: boolean;
}

/**
 * The key purposes of ADR-019 Decision 9, including the two added on
 * 2026-10-10, and their rules.
 *
 * Choices the record leaves open, settled here:
 *
 * - `federation_entity` and `trust_anchor` default to `RS256`, the one
 *   algorithm OpenID Federation 1.0 §3 asks every implementation to verify.
 *   Both rotate manually: a superior's subordinate statement lists the
 *   entity's keys, so a new key needs the superior's statement updated.
 * - `oid4vp_request_signing` is `ES256` only (HAIP §7). It rotates manually:
 *   its X.509 certificate names the key, and the verifier's `x509_hash`
 *   client id is the certificate's hash.
 * - `oid4vp_response_encryption` is an ECDH-ES P-256 key (HAIP §5) whose
 *   public half wallets encrypt to.
 * - `webhook_signing` is a Standard Webhooks HMAC secret that the subscriber
 *   receives once, so it rotates manually.
 * - `upstream_client_assertion` keys are registered with the upstream
 *   provider, so they rotate manually. They are published so the signer can
 *   serve them to a provider that fetches a JWKS.
 * - `agent_upstream_identity` is scoped: each key belongs to one upstream app
 *   identity (ADR-014 §13 `adapter_ref`). The platform holds its public half,
 *   so it is neither published nor rotated automatically.
 * - `agent_wrap` is one AES-256-GCM key per realm. It wraps uploaded upstream
 *   keys and pass-through tokens (ADR-016 §4).
 */
export const KEY_PURPOSES = freezeRegistry({
  token_signing: {
    description: 'Signs access tokens and ID tokens.',
    kind: 'signing',
    algorithms: ['EdDSA', 'RS256', 'ML-DSA-65'],
    defaultAlgorithm: 'EdDSA',
    scoped: false,
    published: true,
    rotation: AUTOMATIC,
    hybridCompanion: 'ML-DSA-65',
  },
  event_signing: {
    description: 'Signs Security Event Tokens and logout tokens.',
    kind: 'signing',
    algorithms: ['EdDSA', 'RS256'],
    defaultAlgorithm: 'EdDSA',
    scoped: false,
    published: true,
    rotation: AUTOMATIC,
  },
  federation_entity: {
    description: "Signs the realm's OpenID Federation entity statements.",
    kind: 'signing',
    algorithms: ['RS256', 'ES256', 'EdDSA'],
    defaultAlgorithm: 'RS256',
    scoped: false,
    published: true,
    rotation: MANUAL,
  },
  trust_anchor: {
    description: 'Signs subordinate statements as a federation trust anchor.',
    kind: 'signing',
    algorithms: ['RS256', 'ES256', 'EdDSA'],
    defaultAlgorithm: 'RS256',
    scoped: false,
    published: true,
    rotation: MANUAL,
    federationOperatorOnly: true,
  },
  oid4vp_request_signing: {
    description: 'Signs OID4VP request objects as the verifier.',
    kind: 'signing',
    algorithms: ['ES256'],
    defaultAlgorithm: 'ES256',
    scoped: false,
    published: true,
    rotation: MANUAL,
  },
  oid4vp_response_encryption: {
    description: 'Decrypts OID4VP responses that wallets encrypt to its public half.',
    kind: 'encryption',
    algorithms: ['ECDH-ES'],
    defaultAlgorithm: 'ECDH-ES',
    scoped: false,
    published: true,
    rotation: AUTOMATIC,
  },
  data_at_rest: {
    description: 'Encrypts data the realm stores.',
    kind: 'symmetric',
    algorithms: ['A256GCM'],
    defaultAlgorithm: 'A256GCM',
    scoped: false,
    published: false,
    rotation: AUTOMATIC,
  },
  cookie_hmac: {
    description: "Signs the realm's browser cookies.",
    kind: 'symmetric',
    algorithms: ['HS256'],
    defaultAlgorithm: 'HS256',
    scoped: false,
    published: false,
    rotation: AUTOMATIC,
  },
  webhook_signing: {
    description: 'Signs the payloads of one webhook subscription.',
    kind: 'symmetric',
    algorithms: ['HS256'],
    defaultAlgorithm: 'HS256',
    scoped: true,
    published: false,
    rotation: MANUAL,
  },
  upstream_client_assertion: {
    description: 'Signs client assertions to one upstream provider (private_key_jwt).',
    kind: 'signing',
    algorithms: ['RS256', 'ES256', 'EdDSA'],
    defaultAlgorithm: 'RS256',
    scoped: true,
    published: true,
    rotation: MANUAL,
  },
  agent_upstream_identity: {
    description: 'The private key of one upstream app identity a credential adapter mints from.',
    kind: 'signing',
    algorithms: ['RS256', 'ES256', 'EdDSA'],
    defaultAlgorithm: 'RS256',
    scoped: true,
    published: false,
    rotation: MANUAL,
  },
  agent_wrap: {
    description: 'Wraps uploaded upstream keys and pass-through tokens.',
    kind: 'symmetric',
    algorithms: ['A256GCM'],
    defaultAlgorithm: 'A256GCM',
    scoped: false,
    published: false,
    rotation: AUTOMATIC,
  },
} as const satisfies Record<string, KeyPurposeDefinition>);

/** Freeze the registry, its entries and their algorithm lists, so no caller can change a rule. */
function freezeRegistry<T extends Record<string, KeyPurposeDefinition>>(registry: T): T {
  for (const definition of Object.values(registry)) {
    Object.freeze(definition.algorithms);
    Object.freeze(definition);
  }
  return Object.freeze(registry);
}

/** A key purpose. See {@link KEY_PURPOSES}. */
export type KeyPurpose = keyof typeof KEY_PURPOSES;

/**
 * The keys every realm gets when it is created (`provisionRealmKeys`): token
 * and event signing, the cookie HMAC and data at rest.
 */
export const STANDARD_REALM_KEY_PURPOSES = Object.freeze([
  'token_signing',
  'event_signing',
  'cookie_hmac',
  'data_at_rest',
] as const satisfies readonly KeyPurpose[]);

/** Whether `value` names a key purpose. */
export function isKeyPurpose(value: string): value is KeyPurpose {
  return Object.hasOwn(KEY_PURPOSES, value);
}

/** The rules of `purpose`. */
export function getKeyPurpose(purpose: KeyPurpose): KeyPurposeDefinition {
  return KEY_PURPOSES[purpose];
}
