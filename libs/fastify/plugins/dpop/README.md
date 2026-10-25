# @qauth-labs/fastify-plugin-dpop

The auth server's way to the shared DPoP proof verifier
([`@qauth-labs/server-dpop`](../../../server/dpop/README.md), RFC 9449), issue #480. The app may
not import a `scope:server` library, so this plugin builds the verifier over the cache plugin's Redis
client and decorates `fastify.dpop`.

```typescript
await fastify.register(dpopPlugin, {
  enabled: env.DPOP_ENABLED, // off: fastify.dpop is null, and no route reads a DPoP header
  origin: env.JWT_ISSUER, // htu is compared with this origin and the request path
});

if (fastify.dpop) {
  const { thumbprint } = await fastify.dpop.verifyRequest(request, {
    accessToken, // at a protected resource: the proof's ath must be its hash
    expectedThumbprint, // when the token, code or refresh token is bound to a key
  });
}
```

`verifyRequest` rejects with a `DpopProofError`, re-exported here with the types the app needs. Its
`error` is the code for the response and its `reason` is for logs and events only.

Used proofs are recorded in Redis under `dpop-jti:` for the verifier's replay window. With Redis
unavailable, every proof is refused.

```bash
pnpm exec nx run fastify-plugin-dpop:test
```
