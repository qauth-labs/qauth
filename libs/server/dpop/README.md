# @qauth-labs/server-dpop

The one DPoP proof verifier of QAuth ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449),
[ADR-014 §3](../../../docs/adr/014-agent-authority-tree.md),
[ADR-017 Decision 14](../../../docs/adr/017-first-party-login.md)). The token endpoint, the admin
API, `resource-guard` and the Authority Tree all check proofs with it; none of them writes its own.

It is a plain library: it imports `jose` and `node:crypto` and nothing else, no Fastify, no Redis
client and no other workspace package (`src/lib/fastify-free.test.ts` holds that down). The auth
server reaches it through a Fastify plugin, and `resource-guard` imports it directly.

Nothing uses it yet. `DPOP_ENABLED` (default `false`) is the switch the endpoints that bind tokens
to a DPoP key will read; until the token endpoint does, the server refuses to start with it on.

## Verify a proof

```typescript
import {
  createDpopVerifier,
  createRedisDpopReplayStore,
  dpopRequestUrl,
} from '@qauth-labs/server-dpop';

const dpop = createDpopVerifier({
  // Used proofs are remembered in Redis; with Redis unavailable, every proof is refused.
  replayStore: createRedisDpopReplayStore(redis),
});

const { thumbprint } = await dpop.verify({
  proof: request.headers.dpop, // the DPoP header: a string, a list, or undefined
  method: request.method,
  // The server's own origin from its configuration, and the request path. Never the proof,
  // the Host header or an absolute-form request target, which dpopRequestUrl refuses.
  url: dpopRequestUrl(publicOrigin, request.url),
  accessToken, // at a protected resource only: ath must be its hash
  expectedThumbprint: token.cnf?.jkt, // when the token, code or session is bound to a key
});
// thumbprint is the RFC 7638 SHA-256 thumbprint of the proof's key: the cnf.jkt of a bound token.
```

`verify` rejects with a `DpopProofError`. Its `error` is the code for the response
(`invalid_dpop_proof` or `use_dpop_nonce`), and its `reason` says which check failed, for logs and
metrics only. Never put the reason on a response.

## What it checks

In this order (RFC 9449 §4.3):

1. Exactly one `DPoP` header, holding one compact JWS of at most 8 KiB.
2. `typ` is exactly `dpop+jwt`.
3. `alg` is on the allowlist. The allowlist is a subset of `DPOP_SIGNATURE_ALGORITHMS`, the
   asymmetric signature algorithms, so `none` and the MAC algorithms can never be on it. The
   default, `DEFAULT_DPOP_ALGORITHMS`, is ES256, ES384, ES512, EdDSA, Ed25519, PS256, PS384 and
   PS512; an endpoint may also allow RS256, RS384 and RS512.
4. The `jwk` header is a public key of the type `alg` needs, with no private or symmetric key
   member (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`, `priv`), its members in canonical
   base64url (so one key has one thumbprint) and an RSA modulus of at most 4096 bits, and the
   signature verifies under it. Only the members RFC 7638 hashes reach the import and the result.
5. No `sub`, `cnf` or `events` claim, so a proof can never pass for a spawn assertion or a security
   event token signed by the same key (ADR-014 §4).
6. `jti` is a string of 1 to 256 characters.
7. `htm` and `htu` match the method and URL the **caller** passes. `htu` is compared after
   RFC 3986 syntax- and scheme-based normalization, ignoring query and fragment. The caller's URL
   is not normalized: a path with a `.` or `..` segment or a backslash is refused, because a
   router serves it as written, not at the path it would normalize to.
8. `iat` is within the window around the server's clock, 60 seconds either way by default.
9. With an access token, `ath` is its base64url SHA-256.
10. With an expected thumbprint, the key has it.
11. With `requireNonce`, the proof carries a nonce the nonce source accepts.
12. Last, the replay store: the proof's key and `jti` are recorded for three windows and a second,
    under a SHA-256 hash, and a proof already recorded is refused. That covers every node whose
    clock is within one window of the recording node's. A store that fails or takes longer than
    250 ms, or answers anything but a first use, refuses the proof.

A proof that fails an earlier check never reaches the store.

## Server-provided nonces

An endpoint may require a nonce (RFC 9449 §8 and §9). Give the verifier a nonce source and pass
`requireNonce: true`:

```typescript
import {
  createDpopVerifier,
  createHmacDpopNonceSource,
  DpopProofError,
} from '@qauth-labs/server-dpop';

const dpop = createDpopVerifier({
  replayStore,
  nonces: createHmacDpopNonceSource({ secret }), // 32+ random bytes, shared by every node
});

try {
  const { thumbprint, nextNonce } = await dpop.verify({ ...check, requireNonce: true });
  reply.header('DPoP-Nonce', nextNonce); // the client uses it for its next proof
} catch (error) {
  if (error instanceof DpopProofError && error.error === 'use_dpop_nonce') {
    reply.header('DPoP-Nonce', error.nonce); // the client retries with it
  }
  throw error;
}
```

`nextNonce` is set only when the call required a nonce. An endpoint that hands a nonce out, through
`nextNonce` or `dpop.nonce()`, requires it from then on: accepting a proof without it would be the
downgrade RFC 9449 §11.3 forbids.

`createHmacDpopNonceSource` keeps no state: the nonce of each 60-second period is an HMAC of the
period's number, accepted in that period and the next. An authorization server and a resource
server each use their own secret, so neither accepts the other's nonces. Any other source fits the
`DpopNonceSource` interface.

## Tests

```bash
pnpm exec nx run server-dpop:test               # unit tests and the shared vectors
pnpm exec nx run server-dpop:test-integration   # the replay store on a real Redis (Docker)
```

`src/lib/vectors.test.ts` runs `test-vectors/dpop/proof.json`: the example proofs of RFC 9449
Figures 2, 7 and 13 and one failing case per check. Every QAuth verifier, in any language, passes
the same file.
