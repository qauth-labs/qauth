// Writes test-vectors/dpop/proof.json: the DPoP proof checks of RFC 9449 §4.3,
// with the RFC's own example proofs and one failing case per check.
// Run by hand when a case is added (`node test-vectors/generators/dpop-proof.mjs`);
// no test runs it, and the tests read the committed file.
//
// Deterministic: the RFC proofs are copied from RFC 9449 Figures 2, 7 and 13,
// the throwaway Ed25519 keys come from fixed seeds, and Ed25519 and HMAC
// signatures carry no randomness, so a re-run writes the same bytes.
import { execFileSync } from 'node:child_process';
import { createHash, createHmac, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { writeFileSync } from 'node:fs';

const OUT = 'test-vectors/dpop/proof.json';

// RFC 9449 Figure 2 (and Figure 5): a token request, iat 1562262616.
const RFC_FIGURE_2 =
  'eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg';
// RFC 9449 Figure 7: a refresh token request, iat 1562265296.
const RFC_FIGURE_7 =
  'eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjY1Mjk2fQ.pAqut2IRDm_De6PR93SYmGBPXpwrAk90e8cP2hjiaG5QsGSuKDYW7_X620BxqhvYC8ynrrvZLTk41mSRroapUA';
// RFC 9449 Figure 13: a protected resource request with ath, iat 1562262618.
const RFC_FIGURE_13 =
  'eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIjoiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0ZWRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNFc05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9.2oW9RP35yRqzhrtNP86L-Ey71EOptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA';
// RFC 9449 Figures 6 and 13: the access token Figure 13's ath is the hash of.
const RFC_ACCESS_TOKEN = 'Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU';
// RFC 9449 Figure 9: the thumbprint of the example key, the jkt of its tokens.
const RFC_JKT = '0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I';
// RFC 9449 Figures 20 and 23: example nonces.
const RFC_NONCE = 'eyJ7S_zG.eyJH0-Z.HX4w-7v';
const RFC_NEXT_NONCE = 'eyJ7S_zG.eyJbYu3.xQmBj-1';

const RFC_TOKEN_URL = 'https://server.example.com/token';
const RFC_RESOURCE_URL = 'https://resource.example.org/protectedresource';

/** An Ed25519 key whose 32-byte seed is SHA-256 of a label that says it is a test key. */
function throwawayKey(label, kid) {
  const seed = createHash('sha256').update(`qauth test-vectors throwaway ${label}`).digest();
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  const privateKey = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  const { kty, crv, x } = createPublicKey(privateKey).export({ format: 'jwk' });
  const { d } = privateKey.export({ format: 'jwk' });
  return { privateKey, jwk: { kty, crv, x, kid }, d };
}

/** RFC 7638 SHA-256 thumbprint of an OKP key: its required members only, in order. */
function thumbprint({ crv, kty, x }) {
  return createHash('sha256').update(JSON.stringify({ crv, kty, x })).digest('base64url');
}

const signingKey = throwawayKey('dpop ed25519 key 1', 'throwaway-test-dpop-ed25519-1');
const otherKey = throwawayKey('dpop ed25519 key 2', 'throwaway-test-dpop-ed25519-2');
const SIGNING_JKT = thumbprint(signingKey.jwk);

const NOW = 1767225600; // 2026-01-01T00:00:00Z
const TOKEN_URL = 'https://as.example.com/token';
const RESOURCE_URL = 'https://rs.example.com/notes';
const ACCESS_TOKEN = 'throwaway-test-access-token-for-the-dpop-vectors';

const b64url = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');

/** A proof for POST TOKEN_URL at NOW, signed by `key`; a member set to undefined is left out. */
function proof({ jti, header = {}, claims = {}, key = signingKey } = {}) {
  const fullHeader = JSON.parse(
    JSON.stringify({ typ: 'dpop+jwt', alg: 'EdDSA', jwk: signingKey.jwk, ...header })
  );
  const payload = JSON.parse(
    JSON.stringify({ jti, htm: 'POST', htu: TOKEN_URL, iat: NOW, ...claims })
  );
  const input = `${b64url(fullHeader)}.${b64url(payload)}`;
  if (fullHeader.alg === 'none') return `${input}.`;
  if (fullHeader.alg.startsWith('HS')) {
    const secret = Buffer.from(fullHeader.jwk.k, 'base64url');
    return `${input}.${createHmac('sha256', secret).update(input).digest('base64url')}`;
  }
  return `${input}.${sign(null, Buffer.from(input), key.privateKey).toString('base64url')}`;
}

const request = (dpop, extra = {}) => ({ dpop, method: 'POST', url: TOKEN_URL, ...extra });
const valid = (jkt) => ({ valid: true, jkt });
const invalid = { valid: false, error: 'invalid_dpop_proof' };
const useNonce = { valid: false, error: 'use_dpop_nonce' };

const RFC_CASES = [
  {
    id: 'rfc9449-figure-2-token-request',
    now: 1562262616,
    requests: [request([RFC_FIGURE_2], { url: RFC_TOKEN_URL })],
    results: [valid(RFC_JKT)],
    notes:
      'RFC 9449 Figure 2, the proof of the token request of Figure 5. jkt is the thumbprint of Figure 9.',
  },
  {
    id: 'rfc9449-figure-7-refresh-request',
    now: 1562265296,
    requests: [request([RFC_FIGURE_7], { url: RFC_TOKEN_URL })],
    results: [valid(RFC_JKT)],
    notes: 'RFC 9449 Figure 7, the proof of a refresh token request.',
  },
  {
    id: 'rfc9449-figure-13-resource-request',
    now: 1562262618,
    requests: [
      request([RFC_FIGURE_13], {
        method: 'GET',
        url: RFC_RESOURCE_URL,
        access_token: RFC_ACCESS_TOKEN,
      }),
    ],
    results: [valid(RFC_JKT)],
    notes:
      'RFC 9449 Figure 13, a protected resource request with the access token of Figure 6; ath is its hash.',
  },
  {
    id: 'rfc9449-figure-13-other-access-token',
    now: 1562262618,
    requests: [
      request([RFC_FIGURE_13], {
        method: 'GET',
        url: RFC_RESOURCE_URL,
        access_token: `${RFC_ACCESS_TOKEN}x`,
      }),
    ],
    results: [invalid],
    notes: 'RFC 9449 §4.3 step 12 and §7: the proof was made for another access token.',
  },
  {
    id: 'rfc9449-figure-2-with-access-token',
    now: 1562262616,
    requests: [request([RFC_FIGURE_2], { url: RFC_TOKEN_URL, access_token: RFC_ACCESS_TOKEN })],
    results: [invalid],
    notes: 'RFC 9449 §4.2 and §7: presented with an access token, a proof needs ath.',
  },
  {
    id: 'rfc9449-figure-2-other-method',
    now: 1562262616,
    requests: [request([RFC_FIGURE_2], { method: 'GET', url: RFC_TOKEN_URL })],
    results: [invalid],
    notes: 'RFC 9449 §4.3 step 8: htm is POST and the request is a GET.',
  },
  {
    id: 'rfc9449-figure-2-other-path',
    now: 1562262616,
    requests: [request([RFC_FIGURE_2], { url: 'https://server.example.com/introspect' })],
    results: [invalid],
    notes: 'RFC 9449 §4.3 step 9: htu names another endpoint of the same server.',
  },
  {
    id: 'rfc9449-figure-13-other-host',
    now: 1562262618,
    requests: [
      request([RFC_FIGURE_13], {
        method: 'GET',
        url: 'https://other-resource.example.org/protectedresource',
        access_token: RFC_ACCESS_TOKEN,
      }),
    ],
    results: [invalid],
    notes: 'RFC 9449 §4.3 step 9: the proof is replayed at another resource server.',
  },
  {
    id: 'rfc9449-figure-2-query-ignored',
    now: 1562262616,
    requests: [request([RFC_FIGURE_2], { url: `${RFC_TOKEN_URL}?client=s6BhdRkqt` })],
    results: [valid(RFC_JKT)],
    notes: 'RFC 9449 §4.3 step 9: the query of the request URL is ignored.',
  },
  {
    id: 'rfc9449-figure-2-normalized-url',
    now: 1562262616,
    requests: [request([RFC_FIGURE_2], { url: 'HTTPS://Server.Example.COM:443/token' })],
    results: [valid(RFC_JKT)],
    notes:
      'RFC 9449 §4.3: htu is compared after syntax- and scheme-based normalization (RFC 3986 §6.2.2, §6.2.3).',
  },
  {
    id: 'rfc9449-figure-2-at-window-edge',
    now: 1562262616 + 60,
    requests: [request([RFC_FIGURE_2], { url: RFC_TOKEN_URL })],
    results: [valid(RFC_JKT)],
    notes: 'iat is exactly 60 seconds old, the edge of the window.',
  },
  {
    id: 'rfc9449-figure-2-too-old',
    now: 1562262616 + 61,
    requests: [request([RFC_FIGURE_2], { url: RFC_TOKEN_URL })],
    results: [invalid],
    notes: 'RFC 9449 §4.3 step 11 and §11.1: iat is 61 seconds old.',
  },
  {
    id: 'rfc9449-figure-2-issued-in-the-future',
    now: 1562262616 - 61,
    requests: [request([RFC_FIGURE_2], { url: RFC_TOKEN_URL })],
    results: [invalid],
    notes: 'RFC 9449 §11.1: iat is 61 seconds ahead of the clock.',
  },
  {
    id: 'rfc9449-figure-2-replayed',
    now: 1562262616,
    requests: [
      request([RFC_FIGURE_2], { url: RFC_TOKEN_URL }),
      request([RFC_FIGURE_2], { url: RFC_TOKEN_URL }),
    ],
    results: [valid(RFC_JKT), invalid],
    notes: 'RFC 9449 §11.1: the same proof presented twice; the second use is a replay.',
  },
  {
    id: 'rfc9449-figure-2-two-headers',
    now: 1562262616,
    requests: [request([RFC_FIGURE_2, RFC_FIGURE_7], { url: RFC_TOKEN_URL })],
    results: [invalid],
    notes: 'RFC 9449 §4.3 step 1: more than one DPoP header.',
  },
  {
    id: 'rfc9449-figure-2-signature-changed',
    now: 1562262616,
    requests: [request([RFC_FIGURE_2.replace(/\.2-GxA6/, '.3-GxA6')], { url: RFC_TOKEN_URL })],
    results: [invalid],
    notes: 'RFC 9449 §4.3 step 6: the first character of the signature is changed.',
  },
  {
    id: 'rfc9449-figure-2-nonce-required',
    now: 1562262616,
    nonce: { accepted: [RFC_NONCE] },
    requests: [request([RFC_FIGURE_2], { url: RFC_TOKEN_URL })],
    results: [useNonce],
    notes: 'RFC 9449 §8 and §11.3: the server requires a nonce (Figure 20) and the proof has none.',
  },
];

const hs256Secret = Buffer.from('qauth throwaway test secret for dpop/proof').toString('base64url');

const GENERATED_CASES = [
  {
    id: 'eddsa-valid',
    requests: [request([proof({ jti: 'dpop-vector-0001' })])],
    results: [valid(SIGNING_JKT)],
    notes: 'Passes every check. jkt ignores the kid member of the jwk (RFC 7638 §3.2).',
  },
  {
    id: 'eddsa-access-token',
    requests: [
      request(
        [
          proof({
            jti: 'dpop-vector-0002',
            claims: {
              htm: 'GET',
              htu: RESOURCE_URL,
              ath: createHash('sha256').update(ACCESS_TOKEN).digest('base64url'),
            },
          }),
        ],
        { method: 'GET', url: RESOURCE_URL, access_token: ACCESS_TOKEN }
      ),
    ],
    results: [valid(SIGNING_JKT)],
    notes: 'A protected resource request whose ath is the hash of the access token.',
  },
  {
    id: 'typ-jwt',
    requests: [request([proof({ jti: 'dpop-vector-0003', header: { typ: 'JWT' } })])],
    results: [invalid],
    notes: 'RFC 9449 §4.3 step 4 and §11.5: typ is JWT.',
  },
  {
    id: 'typ-missing',
    requests: [request([proof({ jti: 'dpop-vector-0004', header: { typ: undefined } })])],
    results: [invalid],
    notes: 'RFC 9449 §4.3 step 4: no typ header.',
  },
  {
    id: 'alg-none',
    requests: [request([proof({ jti: 'dpop-vector-0005', header: { alg: 'none' } })])],
    results: [invalid],
    notes: 'RFC 9449 §4.2 and §11.6: alg is none, with an empty signature.',
  },
  {
    id: 'alg-hs256-symmetric-key',
    requests: [
      request([
        proof({
          jti: 'dpop-vector-0006',
          header: { alg: 'HS256', jwk: { kty: 'oct', k: hs256Secret } },
        }),
      ]),
    ],
    results: [invalid],
    notes:
      'RFC 9449 §4.2 and §4.3 step 7: a MAC algorithm, correctly signed under the throwaway symmetric key its jwk header carries.',
  },
  {
    id: 'alg-not-allowed',
    requests: [request([proof({ jti: 'dpop-vector-0007', header: { alg: 'Ed25519' } })])],
    results: [invalid],
    notes:
      'RFC 9449 §4.3 step 5: Ed25519 (RFC 9864) is an asymmetric algorithm the signature verifies under, but not on this allowlist.',
  },
  {
    id: 'jwk-missing',
    requests: [request([proof({ jti: 'dpop-vector-0008', header: { jwk: undefined } })])],
    results: [invalid],
    notes: 'RFC 9449 §4.2: no jwk header.',
  },
  {
    id: 'jwk-private-key',
    requests: [
      request([
        proof({
          jti: 'dpop-vector-0009',
          key: otherKey,
          header: { jwk: { ...otherKey.jwk, d: otherKey.d } },
        }),
      ]),
    ],
    results: [invalid],
    notes:
      'RFC 9449 §4.3 step 7: the jwk header carries the private member d of the throwaway key that signed the proof.',
  },
  {
    id: 'jwk-other-key',
    requests: [
      request([proof({ jti: 'dpop-vector-0010', key: otherKey, header: { jwk: signingKey.jwk } })]),
    ],
    results: [invalid],
    notes: 'RFC 9449 §4.3 step 6: signed by another key than the one in the jwk header.',
  },
  {
    id: 'jti-missing',
    requests: [request([proof({ jti: undefined })])],
    results: [invalid],
    notes: 'RFC 9449 §4.2 and §4.3 step 3: no jti.',
  },
  {
    id: 'htm-missing',
    requests: [request([proof({ jti: 'dpop-vector-0012', claims: { htm: undefined } })])],
    results: [invalid],
    notes: 'RFC 9449 §4.2 and §4.3 step 3: no htm.',
  },
  {
    id: 'htu-missing',
    requests: [request([proof({ jti: 'dpop-vector-0013', claims: { htu: undefined } })])],
    results: [invalid],
    notes: 'RFC 9449 §4.2 and §4.3 step 3: no htu.',
  },
  {
    id: 'iat-missing',
    requests: [request([proof({ jti: 'dpop-vector-0014', claims: { iat: undefined } })])],
    results: [invalid],
    notes: 'RFC 9449 §4.2 and §4.3 step 3: no iat.',
  },
  {
    id: 'nonce-accepted',
    nonce: { accepted: [RFC_NONCE] },
    requests: [request([proof({ jti: 'dpop-vector-0015', claims: { nonce: RFC_NONCE } })])],
    results: [valid(SIGNING_JKT)],
    notes: 'RFC 9449 §8: the retry carries the nonce the server provided (Figure 21).',
  },
  {
    id: 'nonce-not-accepted',
    nonce: { accepted: [RFC_NEXT_NONCE] },
    requests: [request([proof({ jti: 'dpop-vector-0016', claims: { nonce: RFC_NONCE } })])],
    results: [useNonce],
    notes: 'RFC 9449 §8: the nonce is not one the server accepts any more.',
  },
  {
    id: 'nonce-missing',
    nonce: { accepted: [RFC_NONCE] },
    requests: [request([proof({ jti: 'dpop-vector-0017' })])],
    results: [useNonce],
    notes: 'RFC 9449 §8 and §11.3: the server requires a nonce and the proof has none.',
  },
  {
    id: 'nonce-not-required',
    requests: [request([proof({ jti: 'dpop-vector-0018', claims: { nonce: RFC_NONCE } })])],
    results: [valid(SIGNING_JKT)],
    notes: 'RFC 9449 §4.3 step 10: a server that provides no nonce does not check one.',
  },
  {
    id: 'no-dpop-header',
    requests: [request([])],
    results: [invalid],
    notes: 'RFC 9449 §5 and §7.1: a DPoP request without a proof.',
  },
  {
    id: 'not-a-jwt',
    requests: [request(['not-a-jwt'])],
    results: [invalid],
    notes: 'RFC 9449 §4.3 step 2: the header is not a JWT.',
  },
];

const file = {
  schema: 'qauth-vectors/1-rc.0',
  id: 'dpop/proof',
  description:
    'DPoP proof checks a server runs on the DPoP header of a request (RFC 9449 §4.3). Each case presents input.requests in order to one verifier that starts with an empty replay store, with input.now (Unix seconds) as the current time. A request has dpop, the list of its DPoP header values (an empty list is no header); method and url, the method of the request and the absolute URL it was sent to; and, at a protected resource, access_token, the access token presented with it. The verifier accepts the algorithms ES256 and EdDSA only, and an iat at most 60 seconds from input.now in either direction, edges included. When input.nonce is present the server requires a server-provided nonce and accepts exactly the values in input.nonce.accepted; when it is absent the server provides none and does not check a nonce claim. A proof passes when there is exactly one DPoP header and it is a compact JWS; typ is exactly "dpop+jwt"; alg is on the allowlist; the jwk header is a public key of the type alg needs, with no private or symmetric key members, and the signature verifies under it; jti is a non-empty string; htm equals method exactly; htu equals url after RFC 3986 syntax- and scheme-based normalization, ignoring the query and fragment of both; iat is a number within the window; when access_token is present, ath equals the base64url SHA-256 of its ASCII bytes; when a nonce is required, the nonce claim is one of the accepted values; and no earlier request of the case was accepted with a proof of the same key and jti. expected.results has one entry per request: {"valid": true, "jkt": ...}, where jkt is the RFC 7638 SHA-256 thumbprint of the jwk, base64url; {"valid": false, "error": "use_dpop_nonce"} when the proof passes every other check and its nonce is missing or not accepted; otherwise {"valid": false, "error": "invalid_dpop_proof"}. The rfc9449- cases use the example proofs of RFC 9449 Figures 2, 7 and 13, signed with the RFC\'s own public example key, which has no kid. Every other proof is signed with a throwaway Ed25519 key generated from a fixed seed for this file, whose jwk says so in its kid; jwk-private-key carries that throwaway key\'s private member d in its header on purpose, and alg-hs256-symmetric-key a throwaway symmetric key.',
  source:
    'RFC 9449 §4.2, §4.3, §7, §8 and §11.1, Figures 2, 7, 9, 13, 20, 21 and 23; generated by test-vectors/generators/dpop-proof.mjs with Node.js node:crypto',
  cases: [...RFC_CASES, ...GENERATED_CASES].map(({ id, now, nonce, requests, results, notes }) => ({
    id,
    input: { now: now ?? NOW, ...(nonce === undefined ? {} : { nonce }), requests },
    expected: { results },
    notes,
  })),
};

writeFileSync(OUT, `${JSON.stringify(file, null, 2)}\n`);
execFileSync('pnpm', ['exec', 'oxfmt', OUT], {
  stdio: 'inherit',
});
console.log(`wrote ${OUT} (${file.cases.length} cases)`);
