import { randomBytes } from 'node:crypto';

import {
  type Clock,
  type RecoveryCodeAccount,
  type RecoveryCodeRedemption,
  type RecoveryCodes,
  type RecoveryCodeSet,
  type RecoveryCodeStatus,
  SYSTEM_CLOCK,
} from './ports';

/**
 * RECOVERY CODES (#649; ADR-017 Decision 8, ADR-018 §3; NIST SP 800-63B-4
 * §4.2.1.2 "Issued Recovery Codes"): a set of 10 codes, each of 80 bits from a
 * CSPRNG, shown once and used once. A code stands in for a lost factor on the
 * hosted pages after the first factor; it adds no `amr` value and never `mfa`.
 *
 * A code is shown as 16 lowercase base32 characters (RFC 4648's alphabet,
 * `a`–`z` and `2`–`7`) in four groups of four, `k7qd-2mvw-x4ra-p6tn`: the
 * step grammar's `recovery_codes` personal data. Typed back, case, spaces and
 * dashes are ignored. Only each code's salted hash from the password hasher
 * (Argon2id) is stored, so a stolen table gives no code; at 80 bits a code
 * would resist guessing behind a fast hash too, and the password hasher
 * keeps one way to hash every secret a person types.
 */

/** How many codes a set holds (ADR-017 Decision 8). */
export const RECOVERY_CODE_COUNT = 10;

/** The bits of each code, from a CSPRNG: at least the 64 of ADR-017 Decision 8. */
export const RECOVERY_CODE_BITS = 80;

/** RFC 4648 §6's base32 alphabet, lowercase. */
const BASE32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';

/** The characters of a code, without its dashes: 80 bits at 5 bits a character. */
const RECOVERY_CODE_LENGTH = RECOVERY_CODE_BITS / 5;

/** A code as it is shown: four groups of four base32 characters. */
export const RECOVERY_CODE_PATTERN = /^[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}$/;

/** A code once case, spaces and dashes are taken out: what is hashed. */
const NORMALIZED_PATTERN = /^[a-z2-7]{16}$/;

/** Encode `bytes` in base32, with no padding: 10 bytes make 16 characters. */
function base32(bytes: Uint8Array): string {
  let out = '';
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
    // Keep only the bits not written yet, so the buffer never overflows.
    buffer &= (1 << bits) - 1;
  }
  if (bits > 0) out += BASE32_ALPHABET[(buffer << (5 - bits)) & 31];
  return out;
}

/** A source of random bytes: `crypto.randomBytes`, or a test's. */
export type RandomBytes = (size: number) => Uint8Array;

/** One code, as it is shown, from `random` (a CSPRNG). */
export function generateRecoveryCode(random: RandomBytes = randomBytes): string {
  const bytes = random(RECOVERY_CODE_BITS / 8);
  if (bytes.length !== RECOVERY_CODE_BITS / 8) throw new Error('recovery codes: short random');
  const raw = base32(bytes);
  return [0, 4, 8, 12].map((at) => raw.slice(at, at + 4)).join('-');
}

/** A set of {@link RECOVERY_CODE_COUNT} distinct codes, as they are shown. */
export function generateRecoveryCodeSet(random: RandomBytes = randomBytes): string[] {
  const codes = new Set<string>();
  // Two equal codes of 80 bits are as good as never drawn; a source that
  // repeats itself is a fault, not a reason to loop for ever.
  for (let draws = 0; codes.size < RECOVERY_CODE_COUNT; draws += 1) {
    if (draws >= RECOVERY_CODE_COUNT * 2) throw new Error('recovery codes: the source repeats');
    codes.add(generateRecoveryCode(random));
  }
  return [...codes];
}

/**
 * A code as the person typed it, with case, spaces and dashes taken out: the
 * form that is hashed. `null` when what is left cannot be a code.
 */
export function normalizeRecoveryCode(typed: string): string | null {
  if (typeof typed !== 'string' || typed.length > 64) return null;
  const normalized = typed.replace(/[\s-]/g, '').toLowerCase();
  return NORMALIZED_PATTERN.test(normalized) && normalized.length === RECOVERY_CODE_LENGTH
    ? normalized
    : null;
}

/** The password hasher, as the recovery codes use it: salted Argon2id hashes. */
export interface RecoveryCodeHasher {
  /** A salted hash of `code`, as the password hasher makes one. */
  hash(code: string): Promise<string>;
  /** Whether `code` is the one `hash` was made from, compared in constant time. */
  verify(hash: string, code: string): Promise<boolean>;
}

/**
 * What finds an account by one of its codes alone (#655; ADR-017 Decision 8):
 * an account whose primary identity is a passkey, with no address, has
 * nothing else to name it by when its passkey is lost. Only such an
 * account's sets carry a lookup digest of each code; any other account's
 * codes are found only after a first factor named it.
 */
export interface RecoveryCodeLookup {
  /**
   * The lookup digest of `code`, already normalized, in the realm: the same
   * for the same code and realm, and slow (the auth server's is Argon2id
   * under a salt of the realm), so a stolen table costs a password hash a
   * guess. Never the code.
   */
  digest(input: { readonly realmId: string; readonly code: string }): Promise<string>;
  /**
   * Whether the account's sets carry lookup digests: an account with no
   * address and no password, whose credentials are passkeys. Read when a set
   * is issued.
   */
  findable(account: RecoveryCodeAccount): Promise<boolean>;
}

/** One unused code of a set, as the store holds it. */
export interface StoredRecoveryCode {
  /** The row's id: what {@link RecoveryCodeStore.take} marks used. */
  readonly id: string;
  /** The code's salted hash. */
  readonly hash: string;
}

/** Where the sets live: the auth server's is `user_recovery_codes`. */
export interface RecoveryCodeStore {
  /** Whether the account holds a set, how many of its codes are unused, and whether it is confirmed. */
  status(account: RecoveryCodeAccount): Promise<RecoveryCodeStatus>;
  /** The unused codes of the account's set: none when it holds none. */
  unused(account: RecoveryCodeAccount): Promise<readonly StoredRecoveryCode[]>;
  /**
   * Mark the set `setId` confirmed at `at`, if it is still the account's; a
   * set confirmed before keeps its time. `false` when another set replaced it
   * (or the account holds none). Serialized with {@link replace}.
   */
  confirm(
    account: RecoveryCodeAccount & { readonly setId: string; readonly at: number }
  ): Promise<boolean>;
  /**
   * Replace the account's set, if any, with these hashes, in one write: the
   * new set is unconfirmed. Returns its id, which only this set holds. With
   * `keepConfirmed`, a set the person confirmed stays, nothing is written,
   * and the answer is `null`. `lookupDigests`, when given, are the codes'
   * lookup digests (#655), one for each hash, in the same order.
   */
  replace(
    account: RecoveryCodeAccount & {
      readonly hashes: readonly string[];
      readonly lookupDigests?: readonly string[];
      readonly at: number;
      readonly keepConfirmed: boolean;
    }
  ): Promise<string | null>;
  /**
   * The account an unused code whose lookup digest is `digest` belongs to,
   * in the realm (#655); `null` when there is none, or when two accounts'
   * codes share it. Absent: no set carries lookup digests.
   */
  findByLookupDigest?(input: {
    readonly realmId: string;
    readonly digest: string;
  }): Promise<{ readonly userId: string } | null>;
  /**
   * Mark the code `id` of the account used at `at`, only while it is unused,
   * in one write: `true` when this call took it, `false` when another one did
   * first (or the code is not the account's). `clientId` is the client the
   * sign-in is for, for the write's record.
   */
  take(
    account: RecoveryCodeAccount & {
      readonly id: string;
      readonly at: number;
      readonly clientId: string;
    }
  ): Promise<boolean>;
}

/** What {@link createRecoveryCodeService} is built from. */
export interface RecoveryCodeServiceDependencies {
  readonly store: RecoveryCodeStore;
  readonly hasher: RecoveryCodeHasher;
  readonly clock?: Clock;
  /** The source of random bytes; a CSPRNG. Tests only. */
  readonly random?: RandomBytes;
  /**
   * What finds an account by a code alone (#655), with the store's
   * `findByLookupDigest`. Absent: no code is found before a first factor.
   */
  readonly lookup?: RecoveryCodeLookup;
}

/** The recovery codes' rules over a store: what the engine's port needs but the notices. */
export type RecoveryCodeService = Pick<
  RecoveryCodes,
  'status' | 'issue' | 'redeem' | 'confirm' | 'findAccount'
> & {
  /** A new set in place of the account's, confirmed or not: a regeneration. */
  replace(account: RecoveryCodeAccount): Promise<RecoveryCodeSet>;
};

/**
 * The recovery codes over `store` and the password hasher.
 *
 * - `issue` draws a new set, hashes each code (salted, by the hasher) and
 *   replaces the account's set in one write, unless the account holds a set
 *   the person confirmed by now; the codes go back to the caller once and are
 *   kept nowhere. `replace` (a regeneration) replaces a confirmed set too.
 * - `confirm` confirms the set the person was shown, by its id, and only
 *   while it is still the account's.
 * - `redeem` checks the typed code against every unused hash of the set,
 *   padded to {@link RECOVERY_CODE_COUNT} with the hash of a secret nobody
 *   holds, so a right code and a wrong one cost the same, and the time says
 *   nothing of how many codes are left. An answer that cannot be a code is
 *   checked as long. A match is then taken in one write that only an unused
 *   code passes, so two rounds with the same code take it once.
 * - With a `lookup` (#655), a set issued to an account the lookup calls
 *   findable carries each code's lookup digest, and `findAccount` names the
 *   account an unused code belongs to by the code alone: one digest for any
 *   answer, one that cannot be a code included. It takes nothing; `redeem`
 *   checks and takes the code against the account's salted hashes after.
 */
export function createRecoveryCodeService(
  deps: RecoveryCodeServiceDependencies
): RecoveryCodeService {
  const { store, hasher } = deps;
  const clock = deps.clock ?? SYSTEM_CLOCK;
  const random = deps.random ?? randomBytes;
  const makeDecoy = (): Promise<string> => {
    // On a later microtask: a hasher that throws fails the first redemption,
    // never the engine's construction.
    const made = Promise.resolve().then(() => hasher.hash(base32(random(32))));
    // Awaited, and its failure met, by the first redemption.
    made.catch(() => undefined);
    return made;
  };
  // Made now, so the first redemption after a start costs what every other does.
  let decoy: Promise<string> | undefined = makeDecoy();
  const decoyHash = async (): Promise<string> => {
    decoy ??= makeDecoy();
    try {
      return await decoy;
    } catch (error) {
      decoy = undefined;
      throw error;
    }
  };

  const { lookup } = deps;
  const findByLookupDigest = store.findByLookupDigest?.bind(store);

  const newSet = async (
    { realmId, userId }: RecoveryCodeAccount,
    keepConfirmed: boolean
  ): Promise<RecoveryCodeSet | null> => {
    const codes = generateRecoveryCodeSet(random);
    const normalized = codes.map((code) => {
      const typed = normalizeRecoveryCode(code);
      if (typed === null) throw new Error('recovery codes: a code that cannot be typed');
      return typed;
    });
    const hashes = await Promise.all(normalized.map((code) => hasher.hash(code)));
    const findable =
      lookup !== undefined &&
      findByLookupDigest !== undefined &&
      (await lookup.findable({ realmId, userId }));
    const lookupDigests = findable
      ? await Promise.all(normalized.map((code) => lookup.digest({ realmId, code })))
      : undefined;
    const setId = await store.replace({
      realmId,
      userId,
      hashes,
      ...(lookupDigests === undefined ? {} : { lookupDigests }),
      at: clock.now(),
      keepConfirmed,
    });
    if (setId === null) return null;
    return Object.freeze({ codes: Object.freeze(codes), setId });
  };

  const findAccount =
    lookup === undefined || findByLookupDigest === undefined
      ? undefined
      : async ({ realmId, code }: { readonly realmId: string; readonly code: string }) => {
          const normalized = normalizeRecoveryCode(code);
          // One digest for every answer: one that cannot be a code costs as much.
          const digest = await lookup.digest({
            realmId,
            code: normalized ?? (typeof code === 'string' ? code.slice(0, 64) : ''),
          });
          if (normalized === null) return null;
          const found = await findByLookupDigest({ realmId, digest });
          return found === null ? null : Object.freeze({ userId: found.userId });
        };

  return Object.freeze({
    ...(findAccount === undefined ? {} : { findAccount }),
    status: (account: RecoveryCodeAccount) => store.status(account),

    confirm: ({ realmId, userId, setId }: RecoveryCodeAccount & { readonly setId: string }) =>
      store.confirm({ realmId, userId, setId, at: clock.now() }),

    issue: (account: RecoveryCodeAccount) => newSet(account, true),

    async replace(account: RecoveryCodeAccount) {
      const set = await newSet(account, false);
      if (set === null) throw new Error('recovery codes: a regeneration wrote no set');
      return set;
    },

    async redeem({ realmId, userId, clientId, code }): Promise<RecoveryCodeRedemption> {
      const refused: RecoveryCodeRedemption = Object.freeze({ kind: 'refused' });
      const normalized = normalizeRecoveryCode(code);
      const unused = await store.unused({ realmId, userId });
      if (unused.length > RECOVERY_CODE_COUNT) {
        throw new Error('recovery codes: more unused codes than a set holds');
      }
      const padding = await decoyHash();
      const hashes = [
        ...unused.map((stored) => stored.hash),
        ...Array.from({ length: RECOVERY_CODE_COUNT - unused.length }, () => padding),
      ];
      // Every hash is checked, whatever matched first: the same work for a
      // right code, a wrong one and one that cannot be a code.
      const presented = normalized ?? code.slice(0, 64);
      const matches = await Promise.all(hashes.map((hash) => hasher.verify(hash, presented)));
      if (normalized === null) return refused;
      const index = matches.findIndex((match, at) => match && at < unused.length);
      const match = index < 0 ? undefined : unused[index];
      if (match === undefined) return refused;
      const taken = await store.take({ realmId, userId, clientId, id: match.id, at: clock.now() });
      return taken ? Object.freeze({ kind: 'redeemed' }) : refused;
    },
  });
}
