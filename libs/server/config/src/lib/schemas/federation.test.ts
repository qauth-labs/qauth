import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  type FederationEnv,
  federationEnvSchema,
  resolveStatusListTrustAnchorPems,
  resolveVerifierCertificateChainPems,
  resolveVerifierSigningKeyPem,
  resolveVerifierTrustAnchorPems,
} from './federation';

describe('federationEnvSchema (WALLET_FEDERATION_ENABLED — #232)', () => {
  it('is off by default when unset (epic #231 is incomplete)', () => {
    expect(federationEnvSchema.parse({}).WALLET_FEDERATION_ENABLED).toBe(false);
  });

  it.each([
    ['true', true],
    ['1', true],
    ['false', false],
    ['0', false],
  ])('coerces %s to %s', (raw, expected) => {
    expect(
      federationEnvSchema.parse({ WALLET_FEDERATION_ENABLED: raw }).WALLET_FEDERATION_ENABLED
    ).toBe(expected);
  });

  it.each(['yes', 'TRUE', 'on', ''])(
    'rejects the unrecognized value %o at parse time (never silently truthy)',
    (raw) => {
      expect(() => federationEnvSchema.parse({ WALLET_FEDERATION_ENABLED: raw })).toThrow();
    }
  );

  it('exposes a plain object shape so auth-server can spread it into its env schema', () => {
    // A `.superRefine()`/`.transform()`-wrapped schema has no `.shape`, which
    // would break `z.object({ ...federationEnvSchema.shape })` in env.ts. Both
    // fields wrap themselves (`.transform()`, `z.preprocess()`), which is fine;
    // this asserts no wrapper has been hoisted up to the object.
    expect(Object.keys(federationEnvSchema.shape)).toEqual([
      'WALLET_FEDERATION_ENABLED',
      'OID4VP_VERIFIER_PROFILE',
      'OID4VP_REQUESTED_VCT',
      'OID4VP_SUBJECT_RESOLUTION',
      'OID4VP_SUBJECT_BINDING_CLAIMS',
      'OID4VP_SUBJECT_CLAIM',
      'OID4VP_SUBJECT_CLAIM_ISSUERS',
      'OID4VP_WALLET_INVOCATION_ENDPOINT',
      'OID4VP_STATUS_LIST_TRUST_ANCHORS',
      'OID4VP_STATUS_LIST_TRUST_ANCHORS_PATH',
      'OID4VP_STATUS_LIST_URI_ALLOWLIST',
      'OID4VP_VERIFIER_SIGNING_KEY',
      'OID4VP_VERIFIER_SIGNING_KEY_PATH',
      'OID4VP_VERIFIER_CERTIFICATE_CHAIN',
      'OID4VP_VERIFIER_CERTIFICATE_CHAIN_PATH',
      'OID4VP_VERIFIER_TRUST_ANCHORS',
      'OID4VP_VERIFIER_TRUST_ANCHORS_PATH',
      'OID4VP_RESPONSE_KEY_SECRET',
    ]);
  });
});

describe('federationEnvSchema (OID4VP_RESPONSE_KEY_SECRET — #377 Phase C)', () => {
  it('is undefined when unset — the default posture stores the ephemeral key in the clear', () => {
    expect(federationEnvSchema.parse({}).OID4VP_RESPONSE_KEY_SECRET).toBeUndefined();
  });

  it.each(['', '   '])(
    'treats %o as unset, the way ${VAR:-} materialises an absent variable',
    (raw) => {
      expect(
        federationEnvSchema.parse({ OID4VP_RESPONSE_KEY_SECRET: raw }).OID4VP_RESPONSE_KEY_SECRET
      ).toBeUndefined();
    }
  );

  it('passes a configured value through VERBATIM — decoding and the length rule live in auth-server', () => {
    // 32 bytes, base64. Whether it decodes to exactly one AES-256 key is
    // `resolveOid4vpResponseKeySecret`'s question, asked beside the code that
    // uses it; this layer only bounds the size.
    const secret = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
    expect(
      federationEnvSchema.parse({ OID4VP_RESPONSE_KEY_SECRET: secret }).OID4VP_RESPONSE_KEY_SECRET
    ).toBe(secret);
  });

  it('refuses a value that could not be a 32-byte key however it is encoded', () => {
    expect(() =>
      federationEnvSchema.parse({ OID4VP_RESPONSE_KEY_SECRET: 'A'.repeat(129) })
    ).toThrow();
  });
});

describe('federationEnvSchema (OID4VP_VERIFIER_PROFILE — #299)', () => {
  it('is undefined when unset — absence means "refuse wallet flows", not a default', () => {
    // Unlike WALLET_FEDERATION_ENABLED, this has NO default. `haip-1.0` is not a
    // stricter `oid4vp-1.0-base`, so neither is safe to assume (#296 LOCKED).
    expect(federationEnvSchema.parse({}).OID4VP_VERIFIER_PROFILE).toBeUndefined();
  });

  it.each(['oid4vp-1.0-base', 'haip-1.0'])('accepts the shipped profile id %s', (raw) => {
    expect(
      federationEnvSchema.parse({ OID4VP_VERIFIER_PROFILE: raw }).OID4VP_VERIFIER_PROFILE
    ).toBe(raw);
  });

  it.each(['oid4vp', 'haip', 'HAIP-1.0', 'oid4vp-1.0', 'haip-1.1'])(
    'rejects %o at parse time so a typo fails the boot',
    (raw) => {
      // The dangerous alternative is a typo parsing to `undefined` and reading as
      // a deliberate opt-out, which would look identical to "not configured".
      expect(() => federationEnvSchema.parse({ OID4VP_VERIFIER_PROFILE: raw })).toThrow();
    }
  );

  it.each([
    ['an empty string', ''],
    ['spaces', '   '],
    ['a tab', '\t'],
    ['a newline', '\n'],
  ])('reads %s as unset rather than throwing', (_label, raw) => {
    // `parseEnv` parses the WHOLE composed auth-server env in one `.parse()` at
    // module import, so throwing here would take the process down before it
    // listens — password login and /token included — for a deployment with no
    // interest in wallet federation. A blank value is what an absent variable
    // looks like once compose expands `${OID4VP_VERIFIER_PROFILE:-}`, which is
    // this repo's own default form, so it must land where omission lands.
    expect(
      federationEnvSchema.parse({ OID4VP_VERIFIER_PROFILE: raw }).OID4VP_VERIFIER_PROFILE
    ).toBeUndefined();
  });

  it('still rejects a whitespace-padded profile id (blank is unset, not a trimmer)', () => {
    // Tolerating blanks must not turn into tolerating sloppiness: ' haip-1.0 '
    // is a stated intent that this schema cannot honour verbatim, so it fails
    // loudly instead of being silently normalised into a posture choice.
    expect(() => federationEnvSchema.parse({ OID4VP_VERIFIER_PROFILE: ' haip-1.0 ' })).toThrow();
  });

  it('narrows to the profile id union — the blank-tolerance wrapper must not widen the type', () => {
    // Compile-time assertion, pinned to the EXPORTED type rather than to this
    // call site (a call site can be steered by the contextual type; consumers
    // only ever see `FederationEnv`). If `z.preprocess` had widened the output to
    // `string`/`unknown` this stops compiling — the signal we want, because every
    // downstream `switch` on the profile id would silently lose exhaustiveness
    // and a newly added profile could fall through unhandled.
    const parsed: FederationEnv = federationEnvSchema.parse({
      OID4VP_VERIFIER_PROFILE: 'haip-1.0',
    });
    const profileId: 'oid4vp-1.0-base' | 'haip-1.0' | undefined = parsed.OID4VP_VERIFIER_PROFILE;
    expect(profileId).toBe('haip-1.0');
  });

  it('stays orthogonal to the enable flag — either may be set without the other', () => {
    const parsed = federationEnvSchema.parse({ OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base' });
    expect(parsed.WALLET_FEDERATION_ENABLED).toBe(false);
    expect(parsed.OID4VP_VERIFIER_PROFILE).toBe('oid4vp-1.0-base');
  });
});

describe('federationEnvSchema (OID4VP_REQUESTED_VCT — #239)', () => {
  it('is undefined when unset — the wallet-login entry point is then not offered', () => {
    // No default is possible: a DCQL query with no type constraint asks a wallet
    // for any credential it holds (OID4VP 1.0 §15.6), and an invented default
    // would make a deployment request a credential nobody chose to accept.
    expect(federationEnvSchema.parse({}).OID4VP_REQUESTED_VCT).toBeUndefined();
  });

  it.each(['', '   '])('reads %o as unset, like the other optional federation values', (raw) => {
    expect(federationEnvSchema.parse({ OID4VP_REQUESTED_VCT: raw }).OID4VP_REQUESTED_VCT).toBe(
      undefined
    );
  });

  it('splits a comma-separated list and trims each entry', () => {
    const parsed = federationEnvSchema.parse({
      OID4VP_REQUESTED_VCT: 'urn:eudi:pid:1, https://example.org/vct/employee ,',
    });
    expect(parsed.OID4VP_REQUESTED_VCT).toEqual([
      'urn:eudi:pid:1',
      'https://example.org/vct/employee',
    ]);
  });

  it('rejects a value that lists no usable entry', () => {
    expect(() => federationEnvSchema.parse({ OID4VP_REQUESTED_VCT: ',,' })).toThrow();
  });

  it('rejects an entry containing whitespace', () => {
    expect(() => federationEnvSchema.parse({ OID4VP_REQUESTED_VCT: 'urn:pid 1' })).toThrow();
  });
});

describe('federationEnvSchema (OID4VP_WALLET_INVOCATION_ENDPOINT — #239)', () => {
  it('defaults to the registered custom scheme', () => {
    expect(federationEnvSchema.parse({}).OID4VP_WALLET_INVOCATION_ENDPOINT).toBe('openid4vp://');
  });

  it('accepts a wallet universal link', () => {
    const parsed = federationEnvSchema.parse({
      OID4VP_WALLET_INVOCATION_ENDPOINT: 'https://wallet.example/authorize',
    });
    expect(parsed.OID4VP_WALLET_INVOCATION_ENDPOINT).toBe('https://wallet.example/authorize');
  });

  it.each([
    'openid4vp://',
    'openid4vp://authorize',
    'haip://',
    'eudi-wallet://authorize',
    'mdoc-openid4vp://',
    'x-wallet.vendor+v2://go',
    'https://wallet.example/authorize?x=1',
  ])('accepts the genuine wallet scheme %j', (raw) => {
    expect(
      federationEnvSchema.parse({ OID4VP_WALLET_INVOCATION_ENDPOINT: raw })
        .OID4VP_WALLET_INVOCATION_ENDPOINT
    ).toBe(raw);
  });

  it.each([
    ['no-scheme', 'a relative reference has no Authorization Endpoint to reach'],
    ['openid4vp://#frag', 'a fragment never reaches the wallet'],
    ['openid4vp:// spaced', 'whitespace cannot appear in a URI'],
  ])('rejects %o (%s)', (raw) => {
    expect(() => federationEnvSchema.parse({ OID4VP_WALLET_INVOCATION_ENDPOINT: raw })).toThrow();
  });

  /**
   * The value is rendered into an `href` (`routes/ui/wallet-login.ts`), so a
   * script-capable scheme here is an XSS primitive handed to whoever writes the
   * deployment's environment. Operator-supplied is not the same as trusted: a
   * leaked CI variable, a copy-pasted Helm value or a compromised secrets store
   * all reach this string, and config parsing is where a boot must fail rather
   * than a login page shipping `javascript:` to every user.
   *
   * The shape regex above cannot carry this on its own — `javascript:alert(1)`
   * is a perfectly well-formed absolute URI.
   */
  it.each([
    'javascript:alert(1)',
    'JavaScript:alert(1)',
    'jAvAsCrIpT:alert(document.domain)',
    'vbscript:msgbox(1)',
    'livescript:alert(1)',
    'mocha:alert(1)',
    'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
    'DATA:text/html,<script>alert(1)</script>',
    'blob:https://evil.example/1234',
    'java\tscript:alert(1)',
    'java\u0000script:alert(1)',
    'java script:alert(1)',
    ' javascript:alert(1)',
    'java&#9;script:alert(1)',
    'java&Tab;script:alert(1)',
    '&#106;avascript:alert(1)',
    '&#x6A;avascript:alert(1)',
    'javascript&colon;alert(1)',
  ])('refuses to boot on the script-capable endpoint %j', (raw) => {
    expect(() => federationEnvSchema.parse({ OID4VP_WALLET_INVOCATION_ENDPOINT: raw })).toThrow();
  });
});

/**
 * The VERIFIER identity variables (#377) — QAuth's own ES256 key and X.509
 * chain.
 *
 * This layer validates SHAPE ONLY, exactly as it does for the status-list
 * anchors: that the chain VALIDATES, that the key is P-256 and that the key
 * belongs to the leaf are all `createVerifierSigningMaterial`'s answers at boot.
 * Duplicating certificate parsing here would put two rule sets on a drift
 * course, and `server-config` carries no dependency on `server-federation`.
 */

/** A PEM block of the shape the splitter looks for; never parsed here. */
function certificateBlock(body: string): string {
  return `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----`;
}

const LEAF = certificateBlock('bGVhZg==');
const INTERMEDIATE = certificateBlock('aW50ZXJtZWRpYXRl');
const ANCHOR = certificateBlock('YW5jaG9y');
const KEY = '-----BEGIN PRIVATE KEY-----\nc2lnbmluZw==\n-----END PRIVATE KEY-----';

describe('federationEnvSchema (OID4VP_VERIFIER_SIGNING_KEY — #377)', () => {
  it('is undefined when unset — the default posture provisions no verifier identity', () => {
    const parsed = federationEnvSchema.parse({});

    expect(parsed.OID4VP_VERIFIER_SIGNING_KEY).toBeUndefined();
    expect(parsed.OID4VP_VERIFIER_SIGNING_KEY_PATH).toBeUndefined();
  });

  it('treats a blank value as unset, the way `${VAR:-}` materialises an absent one', () => {
    expect(
      federationEnvSchema.parse({ OID4VP_VERIFIER_SIGNING_KEY: '   ' }).OID4VP_VERIFIER_SIGNING_KEY
    ).toBeUndefined();
  });

  it('trims the inline key', () => {
    expect(
      federationEnvSchema.parse({ OID4VP_VERIFIER_SIGNING_KEY: `\n${KEY}\n` })
        .OID4VP_VERIFIER_SIGNING_KEY
    ).toBe(KEY);
  });

  it('fails the boot when the _PATH form names a file that cannot be read', () => {
    // The operator stated where the key lives, so "not there" is a
    // misconfiguration and never an empty key.
    expect(() =>
      federationEnvSchema.parse({ OID4VP_VERIFIER_SIGNING_KEY_PATH: '/nonexistent/verifier.key' })
    ).toThrow(/cannot be read/);
  });
});

describe('federationEnvSchema (OID4VP_VERIFIER_CERTIFICATE_CHAIN — #377)', () => {
  it('is empty when unset', () => {
    expect(federationEnvSchema.parse({}).OID4VP_VERIFIER_CERTIFICATE_CHAIN).toEqual([]);
  });

  it('splits a concatenated bundle into individual certificates, in order', () => {
    // Load-bearing: `new X509Certificate(bundle)` parses the FIRST certificate
    // and silently ignores the rest, so a two-tier chain passed whole would sign
    // with a leaf whose intermediate never reached the wallet.
    expect(
      federationEnvSchema.parse({
        OID4VP_VERIFIER_CERTIFICATE_CHAIN: `${LEAF}\n${INTERMEDIATE}`,
      }).OID4VP_VERIFIER_CERTIFICATE_CHAIN
    ).toEqual([LEAF, INTERMEDIATE]);
  });

  it('rejects a value that carries no CERTIFICATE block', () => {
    expect(() =>
      federationEnvSchema.parse({ OID4VP_VERIFIER_CERTIFICATE_CHAIN: 'not a certificate' })
    ).toThrow(/OID4VP_VERIFIER_CERTIFICATE_CHAIN/);
  });

  it('rejects a chain longer than the x5c bound the runtime enforces', () => {
    expect(() =>
      federationEnvSchema.parse({
        OID4VP_VERIFIER_CERTIFICATE_CHAIN: Array.from({ length: 9 }, () => LEAF).join('\n'),
      })
    ).toThrow(/more than the 8 supported/);
  });
});

describe('federationEnvSchema — the _PATH forms read a real file (#377)', () => {
  /** Write a fixture file into the OS temp directory and clean it up after. */
  function withFile<T>(contents: string, run: (path: string) => T): T {
    const path = join(mkdtempSync(join(tmpdir(), 'qauth-verifier-')), 'material.pem');
    writeFileSync(path, contents, 'utf-8');
    try {
      return run(path);
    } finally {
      rmSync(dirname(path), { recursive: true, force: true });
    }
  }

  it('reads the signing key from the file the _PATH names', () => {
    withFile(`${KEY}\n`, (path) => {
      expect(
        federationEnvSchema.parse({ OID4VP_VERIFIER_SIGNING_KEY_PATH: path })
          .OID4VP_VERIFIER_SIGNING_KEY_PATH
      ).toBe(KEY);
    });
  });

  it('treats an EMPTY key file as no key rather than as an empty key', () => {
    withFile('   \n', (path) => {
      expect(
        federationEnvSchema.parse({ OID4VP_VERIFIER_SIGNING_KEY_PATH: path })
          .OID4VP_VERIFIER_SIGNING_KEY_PATH
      ).toBeUndefined();
    });
  });

  it('reads and splits the chain from the file the _PATH names', () => {
    withFile(`${LEAF}\n${INTERMEDIATE}\n`, (path) => {
      expect(
        federationEnvSchema.parse({ OID4VP_VERIFIER_CERTIFICATE_CHAIN_PATH: path })
          .OID4VP_VERIFIER_CERTIFICATE_CHAIN_PATH
      ).toEqual([LEAF, INTERMEDIATE]);
    });
  });

  it('reads and splits the anchors from the file the _PATH names', () => {
    withFile(`${ANCHOR}\n`, (path) => {
      expect(
        federationEnvSchema.parse({ OID4VP_VERIFIER_TRUST_ANCHORS_PATH: path })
          .OID4VP_VERIFIER_TRUST_ANCHORS_PATH
      ).toEqual([ANCHOR]);
    });
  });

  it('fails the boot when a chain file holds no CERTIFICATE block', () => {
    withFile('nothing here\n', (path) => {
      expect(() =>
        federationEnvSchema.parse({ OID4VP_VERIFIER_CERTIFICATE_CHAIN_PATH: path })
      ).toThrow(/OID4VP_VERIFIER_CERTIFICATE_CHAIN_PATH/);
    });
  });

  it.each([['OID4VP_VERIFIER_CERTIFICATE_CHAIN_PATH'], ['OID4VP_VERIFIER_TRUST_ANCHORS_PATH']])(
    'fails the boot when %s names a file that cannot be read',
    (variable) => {
      expect(() => federationEnvSchema.parse({ [variable]: '/nonexistent/verifier.pem' })).toThrow(
        /cannot be read/
      );
    }
  );

  it.each([
    ['OID4VP_VERIFIER_SIGNING_KEY_PATH'],
    ['OID4VP_VERIFIER_CERTIFICATE_CHAIN_PATH'],
    ['OID4VP_VERIFIER_TRUST_ANCHORS_PATH'],
  ])('treats a blank %s as unset rather than as an unreadable file', (variable) => {
    expect(() => federationEnvSchema.parse({ [variable]: '   ' })).not.toThrow();
  });
});

describe('federationEnvSchema (OID4VP_VERIFIER_TRUST_ANCHORS — #377)', () => {
  it('is empty when unset, which makes any configured chain refuse at boot', () => {
    expect(federationEnvSchema.parse({}).OID4VP_VERIFIER_TRUST_ANCHORS).toEqual([]);
  });

  it('splits a bundle into individual anchors', () => {
    expect(
      federationEnvSchema.parse({ OID4VP_VERIFIER_TRUST_ANCHORS: `${ANCHOR}\n${LEAF}` })
        .OID4VP_VERIFIER_TRUST_ANCHORS
    ).toEqual([ANCHOR, LEAF]);
  });
});

describe('the verifier-identity resolvers (#377)', () => {
  /** The parsed env a resolver reads, with everything unset by default. */
  function parse(raw: Record<string, string> = {}): FederationEnv {
    return federationEnvSchema.parse(raw);
  }

  it('lets the key _PATH form WIN over the inline one — a key has one value', () => {
    // Not a union, unlike the anchors below. Two sources for a signing key must
    // be a precedence; a set would be meaningless.
    const env = {
      ...parse(),
      OID4VP_VERIFIER_SIGNING_KEY: KEY,
      OID4VP_VERIFIER_SIGNING_KEY_PATH: 'from-file',
    };

    expect(resolveVerifierSigningKeyPem(env)).toBe('from-file');
  });

  it('falls back to the inline key when no path is configured', () => {
    expect(resolveVerifierSigningKeyPem({ ...parse(), OID4VP_VERIFIER_SIGNING_KEY: KEY })).toBe(
      KEY
    );
  });

  it('lets the chain _PATH form WIN rather than concatenating the two', () => {
    // ORDER, not singularity: `x5c` is leaf-first and every link is checked
    // against the next, so interleaving two independently authored chains would
    // produce a sequence whose middle link does not issue the one after it.
    const env = {
      ...parse(),
      OID4VP_VERIFIER_CERTIFICATE_CHAIN: [LEAF],
      OID4VP_VERIFIER_CERTIFICATE_CHAIN_PATH: [INTERMEDIATE, ANCHOR],
    };

    expect(resolveVerifierCertificateChainPems(env)).toEqual([INTERMEDIATE, ANCHOR]);
  });

  it('falls back to the inline chain when the path form is empty', () => {
    expect(
      resolveVerifierCertificateChainPems({
        ...parse(),
        OID4VP_VERIFIER_CERTIFICATE_CHAIN: [LEAF, INTERMEDIATE],
      })
    ).toEqual([LEAF, INTERMEDIATE]);
  });

  it('UNIONS the two anchor sources — an anchor set is a set', () => {
    expect(
      resolveVerifierTrustAnchorPems({
        ...parse(),
        OID4VP_VERIFIER_TRUST_ANCHORS: [ANCHOR],
        OID4VP_VERIFIER_TRUST_ANCHORS_PATH: [LEAF],
      })
    ).toEqual([ANCHOR, LEAF]);
  });

  it('resolves an unconfigured deployment to nothing at all', () => {
    const env = parse();

    expect(resolveVerifierSigningKeyPem(env)).toBeUndefined();
    expect(resolveVerifierCertificateChainPems(env)).toEqual([]);
    expect(resolveVerifierTrustAnchorPems(env)).toEqual([]);
  });

  it('keeps the verifier anchors SEPARATE from the status-list anchors', () => {
    // Sharing them would let a status-issuer CA mint a certificate that
    // identifies this deployment to a wallet.
    const env = {
      ...parse({ OID4VP_STATUS_LIST_TRUST_ANCHORS: LEAF }),
      OID4VP_VERIFIER_TRUST_ANCHORS: [ANCHOR],
    };

    expect(resolveVerifierTrustAnchorPems(env)).toEqual([ANCHOR]);
    expect(resolveStatusListTrustAnchorPems(env)).toEqual([LEAF]);
  });
});
