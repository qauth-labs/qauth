// eslint-disable-next-line @typescript-eslint/triple-slash-reference -- `@types/zxcvbn` does not declare zxcvbn's matcher module, and the declaration must reach every program that compiles this file, the auth-server's included, which consumes this library from source.
/// <reference path="./zxcvbn-matching.d.ts" />
import { z } from 'zod';
import zxcvbn from 'zxcvbn';
import frequencyLists from 'zxcvbn/lib/frequency_lists';
import matching from 'zxcvbn/lib/matching';

/**
 * Password strength validation result
 */
export interface PasswordStrengthResult {
  /**
   * Whether the password meets the minimum strength requirement
   */
  valid: boolean;
  /**
   * Password strength score (0-4)
   * 0: Very weak
   * 1: Weak
   * 2: Fair
   * 3: Good
   * 4: Strong
   */
  score: number;
  /**
   * Optional feedback messages from zxcvbn
   */
  feedback?: string[];
  /**
   * Estimated time to crack (in seconds)
   */
  crackTimeSeconds?: number;
}

/**
 * Password validation configuration schema
 */
export const passwordValidationConfigSchema = z.object({
  /**
   * Minimum password strength score (0-4)
   * 0: Very weak, 1: Weak, 2: Fair, 3: Good, 4: Strong
   */
  minScore: z
    .number()
    .int()
    .min(0, 'Minimum score must be at least 0')
    .max(4, 'Minimum score must not exceed 4'),
});

/**
 * Password validation configuration
 */
export type PasswordValidationConfig = z.infer<typeof passwordValidationConfigSchema>;

/**
 * Password validator interface
 */
export interface PasswordValidator {
  /**
   * Validate password strength using zxcvbn
   *
   * @param password - Password to validate
   * @param userInputs - Words zxcvbn treats as known to an attacker (its
   *   `user_inputs`): the context words of {@link passwordContextWords}.
   * @returns Password strength validation result
   */
  validatePasswordStrength(
    password: string,
    userInputs?: readonly string[]
  ): PasswordStrengthResult;
}

/**
 * The password policy's validators (#528, #634): one per policy, for a server
 * whose realms each set their own minimum length and lowest score
 * (`password.minLength`, `password.minScore`).
 */
export interface PasswordValidators {
  /**
   * The validator of `policy`. Built on first use and cached by policy, so
   * every realm with one policy shares one validator, and a realm's change of
   * policy needs no restart.
   *
   * @param policy - The realm's minimum length and lowest score.
   * @throws {z.ZodError} If `policy` is not one {@link passwordPolicySchema}
   *   accepts; nothing is cached then.
   */
  forPolicy(policy: PasswordPolicy): PasswordPolicyValidator;
}

/**
 * Longest password accepted anywhere, in UTF-16 code units (JavaScript string
 * length). NIST SP 800-63B-4 §3.1.1.2 asks verifiers to accept at least 64
 * characters; 256 leaves ample room for passphrases and password managers.
 *
 * The bound exists because a password is attacker-sized input to CPU-bound
 * work: zxcvbn's matchers grow super-linearly with length, and Argon2id
 * hashes every byte. Request schemas reject anything longer before a handler
 * runs (through {@link passwordSchema}); `validatePasswordStrength` enforces it
 * again for any other caller.
 */
export const PASSWORD_MAX_LENGTH = 256;

/**
 * Request-schema field for a password: a string of at most
 * {@link PASSWORD_MAX_LENGTH} UTF-16 code units. Chain `.min(1)` where an empty
 * password must be refused at the schema.
 *
 * `z.string().max()` alone cannot express this bound. Since Zod 4.5, string
 * `.max()`, `.min()` and `.length()` count Unicode code points, so a password
 * of astral characters (emoji, for example) passes `.max(256)` at up to 512
 * code units, and only `validatePasswordStrength`, which counts `.length`,
 * would catch it, on the register path alone. The check below counts
 * `.length` and raises the issue `.max()` raised with Zod 4.4, same code and
 * same message. It stops the checks after it, so an over-long password yields
 * one issue. `.max()` stays only so the generated OpenAPI document keeps
 * `maxLength`; it can never fail for a value the check accepts.
 */
export const passwordSchema = z
  .string()
  .check((ctx) => {
    if (ctx.value.length > PASSWORD_MAX_LENGTH) {
      ctx.issues.push({
        code: 'too_big',
        origin: 'string',
        maximum: PASSWORD_MAX_LENGTH,
        inclusive: true,
        input: ctx.value,
        continue: false,
      });
    }
  })
  .max(PASSWORD_MAX_LENGTH);

/**
 * How much of a password zxcvbn scores. zxcvbn's cost grows super-linearly
 * with input length, and its own guidance is to score a bounded prefix. A
 * 100-character prefix that is weak makes the whole password weak for our
 * purposes (it errs towards rejecting), and one that is strong already
 * saturates zxcvbn's score of 4.
 */
export const ZXCVBN_MAX_INPUT_LENGTH = 100;

/**
 * How many l33t substitution maps zxcvbn tries for one password.
 *
 * Its l33t matcher enumerates every consistent combination of substitutions
 * for the l33t characters present and runs a full dictionary scan per
 * combination, so the cost is driven by WHICH characters occur, not by how
 * many: all 20 substitutes in its table give 736 maps, and scoring a
 * 100-character password made of them held the event loop for seconds. The
 * length bound above does not limit that. Passwords people choose need a
 * handful of maps (`p@ssw0rd` needs one), so their scores do not change; a
 * password with more is scored with the first 16 enumerated, which can only
 * raise its score slightly. zxcvbn-ts bounds the same work with its
 * `l33tMaxSubstitutions` option.
 *
 * A stopgap: scoring still runs on the event loop, now bounded to a few
 * hundred milliseconds in the worst case.
 */
export const ZXCVBN_MAX_L33T_SUBSTITUTIONS = 16;

// zxcvbn 4.4.2 has no option for this cap, but `l33t_match` obtains its maps
// through `this.enumerate_l33t_subs` on the matching module, the same object
// zxcvbn's entry point requires, so the cap is applied there. The tests pin
// that it takes effect, so an upgrade that stops honouring it fails them.
const enumerateL33tSubs = matching.enumerate_l33t_subs;
matching.enumerate_l33t_subs = function (table) {
  return enumerateL33tSubs.call(this, table).slice(0, ZXCVBN_MAX_L33T_SUBSTITUTIONS);
};

/**
 * Default password validation configuration
 */
export const DEFAULT_PASSWORD_VALIDATION_CONFIG: PasswordValidationConfig = {
  minScore: 2, // Fair
};

/**
 * Create a password validator with the given configuration
 *
 * @param config - Optional partial password validation configuration. Missing values will use defaults.
 * @returns Password validator object with validatePasswordStrength method
 * @throws {z.ZodError} If the configuration is invalid
 *
 * @example
 * ```typescript
 * // Use default minScore (2)
 * const validator = createPasswordValidator();
 *
 * // Override minScore
 * const strictValidator = createPasswordValidator({ minScore: 4 });
 *
 * const result = validator.validatePasswordStrength('mySecurePassword123');
 * if (!result.valid) {
 *   console.log('Password is too weak:', result.feedback);
 * }
 * ```
 */
export function createPasswordValidator(
  config?: Partial<PasswordValidationConfig>
): PasswordValidator {
  // Merge with defaults and validate configuration
  const finalConfig = { ...DEFAULT_PASSWORD_VALIDATION_CONFIG, ...config };
  const validatedConfig = passwordValidationConfigSchema.parse(finalConfig);
  return {
    validatePasswordStrength(
      password: string,
      userInputs?: readonly string[]
    ): PasswordStrengthResult {
      // Empty password check
      if (!password || password.length === 0) {
        return {
          valid: false,
          score: 0,
          feedback: ['Password cannot be empty'],
        };
      }

      if (password.length > PASSWORD_MAX_LENGTH) {
        return {
          valid: false,
          score: 0,
          feedback: [`Password must be at most ${PASSWORD_MAX_LENGTH} characters`],
        };
      }

      // Use zxcvbn to analyze password strength, on a bounded prefix
      // (see ZXCVBN_MAX_INPUT_LENGTH), with the context words as its user
      // inputs when there are any.
      const scored = password.slice(0, ZXCVBN_MAX_INPUT_LENGTH);
      const analysis =
        userInputs !== undefined && userInputs.length > 0
          ? zxcvbn(scored, [...userInputs])
          : zxcvbn(scored);

      // Extract feedback messages
      const feedback: string[] = [];
      if (analysis.feedback.warning) {
        feedback.push(analysis.feedback.warning);
      }
      if (analysis.feedback.suggestions && analysis.feedback.suggestions.length > 0) {
        feedback.push(...analysis.feedback.suggestions);
      }

      // Extract crack time - zxcvbn returns it as number or string, ensure it's a number
      const crackTime = analysis.crack_times_seconds.offline_slow_hashing_1e4_per_second;
      const crackTimeSeconds =
        typeof crackTime === 'number' ? crackTime : parseFloat(crackTime) || undefined;

      return {
        valid: analysis.score >= validatedConfig.minScore,
        score: analysis.score,
        feedback: feedback.length > 0 ? feedback : undefined,
        crackTimeSeconds,
      };
    },
  };
}

/**
 * NIST SP 800-63B-4 §3.1.1.2 "Password Verifiers": a password that may be the
 * only factor of a sign-in is at least 15 characters long. The default of
 * `password.minLength` (`PASSWORD_MIN_LENGTH`); a lower minimum is a recorded
 * deviation while any account can sign in with a password alone (ADR-017
 * Decision 8).
 */
export const PASSWORD_SINGLE_FACTOR_MIN_LENGTH = 15;

/**
 * The lowest minimum length an operator may set: NIST SP 800-63B-4 §3.1.1.2
 * lets a password used only within multi-factor authentication be shorter
 * than 15 characters, and never shorter than 8.
 */
export const PASSWORD_MIN_LENGTH_FLOOR = 8;

/**
 * The highest minimum length an operator may set. NIST SP 800-63B-4 asks a
 * verifier to accept passwords of at least 64 characters; a minimum above that
 * protects nothing more and only refuses passphrases. Widening the bound later
 * is an additive change, narrowing it would not be.
 */
export const PASSWORD_MIN_LENGTH_CEILING = 64;

/** The default minimum length of a new password, in code points. */
export const DEFAULT_PASSWORD_MIN_LENGTH = PASSWORD_SINGLE_FACTOR_MIN_LENGTH;

/**
 * Why a new password was refused (ADR-017 Decision 8): NIST SP 800-63B-4
 * §3.1.1.2 asks the verifier to say why.
 *
 * - `too_long`: more than {@link PASSWORD_MAX_LENGTH} UTF-16 code units, as
 *   typed (checked first, alone: nothing else runs on such a password) or
 *   after NFC normalisation, which every login schema would then refuse.
 * - `too_short`: fewer code points than the minimum, after NFC normalisation.
 * - `blocklisted`: the whole password, ignoring case and the spaces around
 *   it, is a word of zxcvbn's dictionaries or one of the context words. A
 *   password that only contains one is not blocklisted.
 * - `too_weak`: zxcvbn scores it below the lowest score, or it holds an
 *   unpaired surrogate: not text, and hashed as U+FFFD, so what is stored
 *   would be weaker than what was scored.
 */
export const PASSWORD_REJECTION_REASONS = [
  'too_short',
  'too_long',
  'blocklisted',
  'too_weak',
] as const;

/** One of {@link PASSWORD_REJECTION_REASONS}. */
export type PasswordRejectionReason = (typeof PASSWORD_REJECTION_REASONS)[number];

/**
 * The normalisation a new password is hashed after: Unicode NFC. The password
 * credential records it as its normalisation marker, and a verifier applies it
 * to the presented password only when the credential carries the marker.
 */
export const PASSWORD_NORMALIZATION_NFC = 'nfc';

/** The normalisation marker a password credential may carry. */
export type PasswordNormalization = typeof PASSWORD_NORMALIZATION_NFC;

/**
 * A password in Unicode NFC, so two spellings of the same text (a precomposed
 * `é` and an `e` followed by a combining accent, for example) are one password.
 *
 * NFC can lengthen a string: a few characters decompose and do not recompose
 * (U+0958 becomes two code units). Unicode bounds the growth at three times,
 * so a password within {@link PASSWORD_MAX_LENGTH} stays within 768 code units
 * after it.
 */
export function normalizePassword(password: string): string {
  return password.normalize('NFC');
}

/**
 * The presented password a credential is verified with: in NFC when the
 * credential records the NFC marker, as typed when it records none (a password
 * set before the marker existed was hashed as typed).
 */
export function passwordForVerification(
  presented: string,
  normalization: PasswordNormalization | undefined
): string {
  return normalization === PASSWORD_NORMALIZATION_NFC ? normalizePassword(presented) : presented;
}

/**
 * The password policy of a realm (ADR-017 Decision 8): its minimum length, in
 * code points of the NFC form, and its lowest zxcvbn score. There are no
 * composition rules and no periodic change.
 */
export interface PasswordPolicy {
  /** `password.minLength`: 8 to 64, default 15. */
  readonly minLength: number;
  /** `password.minScore`: 0 to 4, default 2. */
  readonly minScore: number;
}

/** What a {@link PasswordPolicy} may hold. */
export const passwordPolicySchema = z.object({
  minLength: z.int().min(PASSWORD_MIN_LENGTH_FLOOR).max(PASSWORD_MIN_LENGTH_CEILING),
  minScore: z.int().min(0).max(4),
});

/** The policy of a realm that sets nothing: 15 code points, score 2. */
export const DEFAULT_PASSWORD_POLICY: PasswordPolicy = Object.freeze({
  minLength: DEFAULT_PASSWORD_MIN_LENGTH,
  minScore: DEFAULT_PASSWORD_VALIDATION_CONFIG.minScore,
});

/**
 * What the password is chosen in, for the blocklist's context words (NIST SP
 * 800-63B-4 §3.1.1.2: "context-specific words, such as the name of the
 * service, the username, and derivatives thereof").
 */
export interface PasswordContext {
  /** The account's address: the address itself, its local part and its domain are context words. */
  readonly email?: string;
  /** The service's name, such as the realm's mail sender name. */
  readonly serviceName?: string;
  /** The realm's name. */
  readonly realmName?: string;
  /** The names of the clients the password is chosen through. */
  readonly clientNames?: readonly string[];
}

/**
 * The context words of `context`, in lower case and NFC, each once: the
 * address, its local part (and the part before a `+` tag) and its domain (and
 * each of its labels but the last); the service, realm and client names.
 * Empty ones are left out.
 */
export function passwordContextWords(context: PasswordContext): string[] {
  const words = new Set<string>();
  const add = (word: string | undefined) => {
    const normalized = word?.normalize('NFC').trim().toLowerCase();
    if (normalized) words.add(normalized);
  };
  if (context.email !== undefined) {
    add(context.email);
    const at = context.email.lastIndexOf('@');
    if (at >= 0) {
      const local = context.email.slice(0, at);
      const domain = context.email.slice(at + 1);
      add(local);
      const tag = local.indexOf('+');
      if (tag > 0) add(local.slice(0, tag));
      add(domain);
      const labels = domain.split('.');
      for (const label of labels.slice(0, -1)) add(label);
    }
  }
  add(context.serviceName);
  add(context.realmName);
  for (const name of context.clientNames ?? []) add(name);
  return [...words];
}

/** Every word of zxcvbn's frequency lists, built on first use and kept. */
let dictionaryWords: ReadonlySet<string> | undefined;

/**
 * Whether the whole of `password` (already NFC), ignoring case and the spaces
 * around it, is a word of zxcvbn's dictionaries or one of `contextWords`.
 * Never a substring match:
 * NIST SP 800-63B-4 §3.1.1.2 says "The entire password SHALL be subject to
 * comparison, not substrings or words that might be contained therein".
 */
function isBlocklisted(password: string, contextWords: readonly string[]): boolean {
  dictionaryWords ??= new Set(Object.values(frequencyLists).flat());
  const lowered = password.toLowerCase();
  const words = dictionaryWords;
  return [lowered, lowered.trim()].some(
    (candidate) => words.has(candidate) || contextWords.includes(candidate)
  );
}

/**
 * An unpaired UTF-16 surrogate: not a character. NFC leaves it as it is, and
 * the hasher encodes the password as UTF-8, where it becomes U+FFFD, so every
 * unpaired surrogate would verify as any other.
 */
const UNPAIRED_SURROGATE = /\p{Cs}/u;

/** The feedback beside `too_weak` for a password with an unpaired surrogate. */
const UNPAIRED_SURROGATE_MESSAGE = 'Password contains characters that are not text';

/** The number of Unicode code points of `value`: what a minimum length counts. */
function codePointLength(value: string): number {
  return [...value].length;
}

/** The message `errors` carries for each reason a password was refused. */
function reasonMessage(reason: PasswordRejectionReason, policy: PasswordPolicy): string {
  switch (reason) {
    case 'too_long':
      return `Password must be at most ${PASSWORD_MAX_LENGTH} characters`;
    case 'too_short':
      return `Password must be at least ${policy.minLength} characters`;
    case 'blocklisted':
      return 'Password is a commonly used word or password, or names this service or account';
    case 'too_weak':
      return 'Password is too easy to guess';
  }
}

/** The outcome of checking a new password against a {@link PasswordPolicy}. */
export type PasswordPolicyCheck =
  | {
      readonly valid: true;
      /** The password in NFC: what is hashed and stored. */
      readonly password: string;
      /** The marker the credential records, so a verifier normalises too. */
      readonly normalization: PasswordNormalization;
      /** The zxcvbn score, 0 to 4. */
      readonly score: number;
    }
  | {
      readonly valid: false;
      /** Every reason the password was refused, in the order checked. */
      readonly reasons: readonly PasswordRejectionReason[];
      /** One message per reason, then zxcvbn's own feedback when it is too weak. */
      readonly feedback: readonly string[];
    };

/** A validator of one {@link PasswordPolicy}. */
export interface PasswordPolicyValidator {
  /** The policy it checks. */
  readonly policy: PasswordPolicy;
  /**
   * Check a new password (ADR-017 Decision 8), in this order:
   *
   * 1. its length as typed: more than {@link PASSWORD_MAX_LENGTH} UTF-16 code
   *    units is `too_long`, and nothing else runs, neither normalisation nor
   *    scoring nor hashing;
   * 2. NFC normalisation ({@link normalizePassword}); a password it lengthens
   *    past {@link PASSWORD_MAX_LENGTH} is `too_long` too, alone;
   * 3. fewer code points than `minLength` is `too_short`;
   * 4. the whole password, ignoring case and the spaces around it, equal to a
   *    word of zxcvbn's dictionaries or a context word is `blocklisted`;
   * 5. a zxcvbn score, with the context words as its user inputs, below
   *    `minScore`, or an unpaired surrogate anywhere, is `too_weak`.
   *
   * Every reason found is returned. An accepted password comes back in NFC,
   * which is what the caller hashes, with the marker to store beside it.
   */
  check(password: string, context?: PasswordContext): PasswordPolicyCheck;
}

/**
 * Create the validator of `policy`, the one password policy for every new
 * password (ADR-017 Decision 8): wherever QAuth stores a password a person
 * chose, it is checked here and hashed in the form this returns.
 *
 * @param policy - Missing values take {@link DEFAULT_PASSWORD_POLICY}'s.
 * @throws {z.ZodError} If the policy is out of bounds: a minimum length
 *   outside 8 to 64, or a score outside 0 to 4.
 */
export function createPasswordPolicyValidator(
  policy?: Partial<PasswordPolicy>
): PasswordPolicyValidator {
  const checked = Object.freeze(
    passwordPolicySchema.parse({ ...DEFAULT_PASSWORD_POLICY, ...policy })
  );
  const strength = createPasswordValidator({ minScore: checked.minScore });
  return Object.freeze({
    policy: checked,
    check(password: string, context: PasswordContext = {}): PasswordPolicyCheck {
      if (password.length > PASSWORD_MAX_LENGTH) {
        return {
          valid: false,
          reasons: ['too_long'],
          feedback: [reasonMessage('too_long', checked)],
        };
      }
      const normalized = normalizePassword(password);
      // A password NFC lengthened past the bound (see normalizePassword):
      // every login schema bounds the password at PASSWORD_MAX_LENGTH, so its
      // NFC spelling, which the marker says is the same password, could never
      // sign in.
      if (normalized.length > PASSWORD_MAX_LENGTH) {
        return {
          valid: false,
          reasons: ['too_long'],
          feedback: [reasonMessage('too_long', checked)],
        };
      }
      const contextWords = passwordContextWords(context);
      const reasons: PasswordRejectionReason[] = [];
      if (codePointLength(normalized) < checked.minLength) reasons.push('too_short');
      if (isBlocklisted(normalized, contextWords)) reasons.push('blocklisted');
      // zxcvbn scores a bounded prefix anyway (ZXCVBN_MAX_INPUT_LENGTH).
      const scored = strength.validatePasswordStrength(
        normalized.slice(0, ZXCVBN_MAX_INPUT_LENGTH),
        contextWords
      );
      const unpaired = UNPAIRED_SURROGATE.test(normalized);
      if (!scored.valid || unpaired) reasons.push('too_weak');
      if (reasons.length > 0) {
        return {
          valid: false,
          reasons,
          feedback: [
            ...reasons.map((reason) => reasonMessage(reason, checked)),
            ...(unpaired ? [UNPAIRED_SURROGATE_MESSAGE] : []),
            ...(scored.valid ? [] : (scored.feedback ?? [])),
          ],
        };
      }
      return {
        valid: true,
        password: normalized,
        normalization: PASSWORD_NORMALIZATION_NFC,
        score: scored.score,
      };
    },
  });
}

/**
 * Create the password validators of {@link PasswordValidators}: a validator
 * per policy, built with {@link createPasswordPolicyValidator} on first use
 * and kept. A policy the schema refuses throws and is not kept.
 *
 * @example
 * ```typescript
 * const validators = createPasswordValidators();
 *
 * // The policy of the realm the password is chosen in.
 * const result = validators
 *   .forPolicy({ minLength: 15, minScore: 2 })
 *   .check(password, { email, realmName, serviceName });
 * if (result.valid) {
 *   const hash = await hasher.hashPassword(result.password);
 * }
 * ```
 */
export function createPasswordValidators(): PasswordValidators {
  const byPolicy = new Map<string, PasswordPolicyValidator>();
  return Object.freeze({
    forPolicy(policy: PasswordPolicy): PasswordPolicyValidator {
      const key = `${policy.minLength}:${policy.minScore}`;
      const cached = byPolicy.get(key);
      if (cached !== undefined) return cached;
      const validator = createPasswordPolicyValidator({
        minLength: policy.minLength,
        minScore: policy.minScore,
      });
      byPolicy.set(key, validator);
      return validator;
    },
  });
}
