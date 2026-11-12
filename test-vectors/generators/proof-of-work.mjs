// Writes test-vectors/interaction/proof-of-work.json: the built-in proof of
// work of the Interaction API's `captcha` step (#643, #1082). Run by hand when
// a case is added; no test runs it, and the tests read the committed file.
//
//   node test-vectors/generators/proof-of-work.mjs
//
// Every value comes from Node.js node:crypto and a search that starts at the
// same place on every run, so the file is rewritten byte for byte. The rule it
// encodes is the contract's (`libs/shared/interaction-contract`, the `pow`
// params of the `captcha` step), written here a second time on purpose: the
// server's check and the page's solver are tested against it, not against
// each other.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';

const OUT = 'test-vectors/interaction/proof-of-work.json';

/** A nonce: decimal ASCII digits, no sign, no leading zero, at most 16 digits. */
const NONCE = /^(?:0|[1-9][0-9]{0,15})$/;

/** The puzzle of most cases: the base64url of "qauth-pow-test-vector-of-32-bytes". */
const CHALLENGE = 'cWF1dGgtcG93LXRlc3QtdmVjdG9yLW9mLTMyLWJ5dGVz';
/** The `captcha` step's example challenge in the contract. */
const CONTRACT_EXAMPLE = 'Qm9vbGVhbi1ub3QtYS1yZWFsLWNoYWxsZW5nZS0zMmI';
/** A puzzle whose nonce 0 solves it: the base64url of "qauth-pow-vector-nonce-zero-0001". */
const ZERO_CHALLENGE = 'cWF1dGgtcG93LXZlY3Rvci1ub25jZS16ZXJvLTAwMDE';

const digestOf = (challenge, token) =>
  createHash('sha256')
    .update(Buffer.from(`${challenge}:${token}`, 'utf8'))
    .digest();

function leadingZeroBits(digest) {
  let bits = 0;
  for (const byte of digest) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    return bits + Math.clz32(byte) - 24;
  }
  return bits;
}

const accepted = (challenge, difficulty, token) =>
  NONCE.test(token) && leadingZeroBits(digestOf(challenge, token)) >= difficulty;

/** The smallest nonce that solves the puzzle. */
function smallest(challenge, difficulty) {
  for (let nonce = 0n; ; nonce += 1n) {
    if (accepted(challenge, difficulty, String(nonce))) return String(nonce);
  }
}

/** The first token `form(n)`, n = 1, 2, …, whose digest meets `test`. */
function firstWhere(challenge, form, test, start = 1n, step = 1n) {
  for (let n = start; ; n += step) {
    const token = form(n);
    if (test(digestOf(challenge, token))) return token;
  }
}

const atLeast = (bits) => (digest) => leadingZeroBits(digest) >= bits;
const exactly = (bits) => (digest) => leadingZeroBits(digest) === bits;
const decimal = (n) => String(n);
const ARABIC_INDIC = '٠١٢٣٤٥٦٧٨٩';

if (!accepted(ZERO_CHALLENGE, 1, '0')) throw new Error('ZERO_CHALLENGE: nonce 0 must solve it');

/** A refused form whose hash alone meets the difficulty, so only its form refuses it. */
const formOnly = (form, start) => firstWhere(CHALLENGE, form, atLeast(4), start);

const cases = [
  {
    id: 'smallest-at-difficulty-12',
    input: { challenge: CHALLENGE, difficulty: 12, captcha_token: smallest(CHALLENGE, 12) },
    notes:
      'The challenge is hashed as the text it is: its base64url is not decoded first. The reference solver tries 0, 1, 2 and so on, and returns this nonce.',
  },
  {
    id: 'smallest-at-difficulty-16',
    input: { challenge: CHALLENGE, difficulty: 16, captcha_token: smallest(CHALLENGE, 16) },
  },
  {
    id: 'contract-example',
    input: {
      challenge: CONTRACT_EXAMPLE,
      difficulty: 18,
      captcha_token: smallest(CONTRACT_EXAMPLE, 18),
    },
    notes:
      'The example of the captcha step in the Interaction API contract (/interaction/v1-rc.0/openapi.json): its params and its answer.',
  },
  {
    id: 'exactly-the-difficulty',
    input: {
      challenge: CHALLENGE,
      difficulty: 12,
      captcha_token: firstWhere(CHALLENGE, decimal, exactly(12), 0n),
    },
    notes:
      'Exactly 12 leading zero bits pass a difficulty of 12. It is a larger solution than the smallest one, and any solution passes.',
  },
  {
    id: 'one-bit-short',
    input: {
      challenge: CHALLENGE,
      difficulty: 12,
      captcha_token: firstWhere(CHALLENGE, decimal, exactly(11), 0n),
    },
    notes: '11 leading zero bits do not pass a difficulty of 12.',
  },
  {
    id: 'bits-read-from-the-most-significant',
    input: {
      challenge: CHALLENGE,
      difficulty: 7,
      captcha_token: firstWhere(CHALLENGE, decimal, (digest) => digest[0] === 0x01, 0n),
    },
    notes:
      "The digest's first byte is 0x01: seven zero bits before the first one bit, read from the most significant bit.",
  },
  {
    id: 'least-significant-bits-do-not-count',
    input: {
      challenge: CHALLENGE,
      difficulty: 7,
      captcha_token: firstWhere(CHALLENGE, decimal, (digest) => digest[0] === 0x80, 0n),
    },
    notes:
      "The digest's first byte is 0x80: its first bit is one, so it has no leading zero bit, though its seven least significant bits are zero.",
  },
  {
    id: 'nonce-zero',
    input: { challenge: ZERO_CHALLENGE, difficulty: 1, captcha_token: '0' },
    notes: '0 is a nonce: the one nonce that starts with the digit 0.',
  },
  {
    id: 'sixteen-digits',
    input: {
      challenge: CHALLENGE,
      difficulty: 4,
      captcha_token: firstWhere(CHALLENGE, decimal, atLeast(4), 9999999999999999n, -1n),
    },
    notes:
      'The longest nonce, 16 digits, past the largest integer a JavaScript number holds exactly: a solver that counts in doubles never reaches it.',
  },
  {
    id: 'seventeen-digits',
    input: {
      challenge: CHALLENGE,
      difficulty: 4,
      captcha_token: formOnly(decimal, 10n ** 16n),
    },
    notes: 'Its digest would pass; 17 digits are one too many.',
  },
  {
    id: 'leading-zero',
    input: { challenge: CHALLENGE, difficulty: 4, captcha_token: formOnly((n) => `0${n}`) },
    notes: 'Its digest would pass; a nonce other than 0 does not start with the digit 0.',
  },
  {
    id: 'plus-sign',
    input: { challenge: CHALLENGE, difficulty: 4, captcha_token: formOnly((n) => `+${n}`) },
    notes: 'Its digest would pass; a nonce has no sign.',
  },
  {
    id: 'trailing-newline',
    input: { challenge: CHALLENGE, difficulty: 4, captcha_token: formOnly((n) => `${n}\n`) },
    notes:
      'Its digest would pass; a line feed is not a digit. A pattern whose end anchor also matches before a final line feed, as `$` does in Python, PCRE and Perl, takes it: match the whole string.',
  },
  {
    id: 'non-ascii-digits',
    input: {
      challenge: CHALLENGE,
      difficulty: 4,
      captcha_token: formOnly((n) =>
        [...String(n)].map((digit) => ARABIC_INDIC[Number(digit)]).join('')
      ),
    },
    notes:
      "Its digest would pass; Arabic-Indic digits match \\d in some pattern engines, Python's and .NET's among them, but a nonce is ASCII 0 to 9.",
  },
];

const file = {
  schema: 'qauth-vectors/1-rc.0',
  id: 'interaction/proof-of-work',
  description:
    "The built-in proof of work of the Interaction API's captcha step, whose params are provider pow, a challenge and a difficulty: whether a captcha_token solves the puzzle. input.challenge is the step's challenge (base64url text), input.difficulty its difficulty (1 to 32) and input.captcha_token the answer. expected.digest is the SHA-256 of the UTF-8 bytes of the challenge, a colon and the token (<challenge>:<captcha_token>), with the challenge as the text it is, not decoded; it is base64url without padding. expected.leading_zero_bits is how many bits of that digest are zero before its first one bit, reading the first byte first and each byte from its most significant bit. expected.accepted is true only when captcha_token is a nonce, that is one to 16 ASCII digits 0 to 9 with no sign and no leading zero (0 itself is a nonce), and leading_zero_bits is at least difficulty. expected.smallest_solution is true only when the token is accepted and no smaller nonce is: the nonce a solver that tries 0, 1, 2 and so on returns. digest and leading_zero_bits are given for every token, so a case refused for its form shows that its digest alone would have passed.",
  source:
    'The captcha step of the Interaction API v1-rc.0 contract (#643, #1082); generated by test-vectors/generators/proof-of-work.mjs with Node.js node:crypto',
  cases: cases.map(({ id, input, notes }) => {
    const digest = digestOf(input.challenge, input.captcha_token);
    const isAccepted = accepted(input.challenge, input.difficulty, input.captcha_token);
    return {
      id,
      input,
      expected: {
        digest: digest.toString('base64url'),
        leading_zero_bits: leadingZeroBits(digest),
        accepted: isAccepted,
        smallest_solution:
          isAccepted && smallest(input.challenge, input.difficulty) === input.captcha_token,
      },
      ...(notes === undefined ? {} : { notes }),
    };
  }),
};

writeFileSync(OUT, `${JSON.stringify(file, null, 2)}\n`);
execFileSync('pnpm', ['exec', 'oxfmt', OUT], { stdio: 'inherit' });
console.log(`wrote ${OUT} (${file.cases.length} cases)`);
