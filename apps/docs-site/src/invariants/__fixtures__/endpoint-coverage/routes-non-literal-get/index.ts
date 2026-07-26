// Mirrors apps/auth-server/src/app/routes/auth/resend-verification.ts's
// `fastify.redis.get(lastSentKey)` — a `.get(` call whose first argument is
// an identifier, not a string literal. Must NOT be extracted as a route.
export default async function (fastify: {
  redis: { get: (key: string) => Promise<string | null> };
}) {
  const lastSentKey = 'some-computed-key';
  await fastify.redis.get(lastSentKey);
}
